use crate::util::join_base_url_and_path;
use anyhow::{Context, Result};
use oauth2::{
    AccessToken, ClientId, ClientSecret, EndpointNotSet, ExtraTokenFields, RefreshToken,
    StandardErrorResponse, StandardTokenResponse, TokenResponse as _, TokenUrl, reqwest,
};
use openidconnect::{
    Client, EmptyAdditionalClaims, IdTokenFields, IdTokenVerifier, IssuerUrl, JsonWebKeySet,
    JsonWebKeySetUrl, Nonce, TokenResponse as _,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
        CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
        CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse,
        CoreTokenType,
    },
};
use url::Url;

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // we just want to have all fields
pub(super) struct TokenResponse {
    pub(super) user: Option<String>,
    pub(super) access_token: AccessToken,
    pub(super) expires_in: u64,
    pub(super) refresh_token: RefreshToken,
    pub(super) refresh_expires_in: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RefreshExpiresInField {
    refresh_expires_in: u64,
}

impl ExtraTokenFields for RefreshExpiresInField {}

impl TokenResponse {
    fn from_response(
        response: &WildliveTokenResponse,
        id_token_verifier: &IdTokenVerifier<'_, CoreJsonWebKey>,
    ) -> Result<Self> {
        let refresh_token = response
            .refresh_token()
            .cloned()
            .unwrap_or_else(|| RefreshToken::new(String::new()));
        debug_assert!(
            !refresh_token.secret().is_empty(),
            "refresh token should be present"
        );

        let user = response
            .id_token()
            .ok_or(openidconnect::ClaimsVerificationError::Unsupported(
                "ID token is missing".to_string(),
            ))?
            .claims(id_token_verifier, |_n: Option<&Nonce>| {
                // we just want the username for display purposes, so we skip nonce verification
                Ok(())
            })
            .context("failed to extract user from ID token")?
            .preferred_username()
            .map(|e| e.to_string());

        Ok(Self {
            user,
            access_token: response.access_token().clone(),
            expires_in: response.expires_in().map_or(0, |d| d.as_secs()),
            refresh_token,
            refresh_expires_in: response.extra_fields().extra_fields().refresh_expires_in,
        })
    }
}

type WildliveIdTokenFields = IdTokenFields<
    EmptyAdditionalClaims,
    RefreshExpiresInField,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type WildliveTokenResponse = StandardTokenResponse<WildliveIdTokenFields, CoreTokenType>;
type WildliveClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
    HasUserInfoUrl = EndpointNotSet,
> = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    WildliveTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

pub async fn retrieve_access_and_refresh_token(
    http_client: &reqwest::Client,
    wildlive_config: &crate::config::Oidc,
    jwks: CoreJsonWebKeySet,
    refresh_token: &RefreshToken,
) -> Result<TokenResponse> {
    let client_id = ClientId::new(wildlive_config.client_id.clone());

    let token_url = TokenUrl::from_url(
        join_base_url_and_path(&wildlive_config.issuer, "protocol/openid-connect/token")
            .context("invalid url")?,
    );

    let mut client = WildliveClient::new(
        client_id,
        IssuerUrl::from_url(wildlive_config.issuer.clone()),
        jwks,
    )
    .set_token_uri(token_url);

    if let Some(client_secret) = wildlive_config.client_secret.as_ref() {
        client = client.set_client_secret(ClientSecret::new(client_secret.into()));
    }

    let id_token_verifier = client.id_token_verifier();

    let refresh_token_request = client.exchange_refresh_token(refresh_token);

    TokenResponse::from_response(
        &refresh_token_request
            .request_async(http_client)
            .await
            .context("auth key is invalid")?,
        &id_token_verifier,
    )
}

pub async fn retrieve_jwks(
    http_client: &reqwest::Client,
    issuer_url: &Url,
) -> Result<CoreJsonWebKeySet> {
    let jwks_url = join_base_url_and_path(issuer_url, "protocol/openid-connect/certs")
        .context("invalid url")?;

    // let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;
    // Ok(provider_metadata.jwks())

    let jwks_url = JsonWebKeySetUrl::from_url(jwks_url);

    JsonWebKeySet::fetch_async(&jwks_url, http_client)
        .await
        .context("fetching JWKS failed")
}

#[cfg(test)]
mod tests {

    use super::*;
    use chrono::{Duration, Utc};
    use httptest::{Expectation, all_of, matchers, responders::status_code};
    use oauth2::{EmptyExtraTokenFields, basic::BasicTokenType};
    use openidconnect::{
        Audience, EndUserEmail, EndUserName, EndUserUsername, LocalizedClaim, StandardClaims,
        SubjectIdentifier,
        core::{
            CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreRsaPrivateSigningKey,
            CoreTokenResponse,
        },
    };

    const TEST_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
	    MIIEogIBAAKCAQEAxIm5pngAgY4V+6XJPtlATkU6Gbcen22M3Tf16Gwl4uuFagEp\n\
	    SQ4u/HXvcyAYvdNfAwR34nsAyS1qFQasWYtcU4HwmFvo5ADfdJpfo6myRiGN3ocA\n\
	    4+/S1tH8HqLH+w7U/9SopwUP0n0+N0UaaFA1htkRY4zNWEDnJ2AVN2Vi0dUtS62D\n\
	    jOfvz+QMd04mAZaLkLdSxlHCYKjx6jmTQEbVFwSt/Pm1MryF7gkXg6YeiNG6Ehgm\n\
	    LUHv50Jwt1salVH9/FQVNkqiVivHNAW4cEVbuTZJl8TjtQn6MnOZSP7n8TkonrUd\n\
	    ULoIxIl3L+kneJABBaQ6zg52w00W1MXwlu+C8wIDAQABAoIBACW+dWLc5Ov8h4g+\n\
	    fHmPa2Qcs13A5yai+Ux6tMUgD96WcJa9Blq7WJavZ37qiRXbhAGmWAesq6f3Cspi\n\
	    77J6qw52g+gerokrCb7w7rEVo+EIDKDRuIANzKXoycxwYot6e7lt872voSxBVTN0\n\
	    F/A0hzMQeOBvZ/gs7reHIkvzMpktSyKVJOt9ie1cZ1jp7r1bazbFs2qIyDc5Z521\n\
	    BQ6GgRyNJ5toTttmF5ZxpSQXWyvumldWL5Ue9wNEIPjRgsL9UatqagxgmouGxEOL\n\
	    0F9bFWUFlrsqTArTWNxg5R0zFwfzFqidx0HwyF9SyidVq9Bz8/FtgVe2ed4u7snm\n\
	    vYOUbsECgYEA7yg6gyhlQvA0j5MAe6rhoMD0sYRG07ZR0vNzzZRoud9DSdE749f+\n\
	    ZvqUqv3Wuv5p97dd4sGuMkzihXdGqcpWO4CAbalvB2CB5HKVMIKR5cjMIzeVE17v\n\
	    0Hcdd2Spx6yMahFX3eePLl3wDDLSP2ITYi6m4SGckGwd5BeFkn4gNyMCgYEA0mEd\n\
	    Vt2bGF9+5sFfsZgd+3yNAnqLGZ+bxZuYcF/YayH8dKKHdrmhTJ+1w78JdFC5uV2G\n\
	    F75ubyrEEY09ftE/HNG90fanUAYxmVJXMFxxgMIE8VqsjiB/i1Q3ofN2HOlOB1W+\n\
	    4e8BEXrAxCgsXMGCwU73b52474/BDq4Bh1cNKfECgYB4cfw1/ewxsCPogxJlNgR4\n\
	    H3WcyY+aJGJFKZMS4EF2CvkqfhP5hdh8KIsjKsAwYN0hgtnnz79ZWdtjeFTAQkT3\n\
	    ppoHoKNoRbRlR0fXrIqp/VzCB8YugUup47OVY78V7tKwwJdODMbRhUHWAupcPZqh\n\
	    gflNvM3K9oh/TVFaG+dBnQKBgHE2mddZQlGHcn8zqQ+lUN05VZjz4U9UuTtKVGqE\n\
	    6a4diAIsRMH7e3YErIg+khPqLUg3sCWu8TcZyJG5dFJ+wHv90yzek4NZEe/0g78e\n\
	    wGYOAyLvLNT/YCPWmmmo3vMIClmgJyzmtah2aq4lAFqaOIdWu4lxU0h4D+iac3Al\n\
	    xIvBAoGAZtOeVlJCzmdfP8/J1IMHqFX3/unZEundqL1tiy5UCTK/RJTftr6aLkGL\n\
	    xN3QxN+Kuc5zMyHeQWY9jKO8SUwyuzrCuwduzzqC1OXEWinfcvCPg1yotRxgPGsV\n\
	    Wj4iz6nkuRK0fTLfTu6Nglx6mjX8Q3rz0UUFVjOL/gpgEWxzoHk=\n\
	    -----END RSA PRIVATE KEY-----";

    const TEST_JWK: &str = "{\
        \"kty\":\"RSA\",
        \"use\":\"sig\",
        \"n\":\"xIm5pngAgY4V-6XJPtlATkU6Gbcen22M3Tf16Gwl4uuFagEpSQ4u_HXvcyAYv\
            dNfAwR34nsAyS1qFQasWYtcU4HwmFvo5ADfdJpfo6myRiGN3ocA4-_S1tH8HqLH-w\
            7U_9SopwUP0n0-N0UaaFA1htkRY4zNWEDnJ2AVN2Vi0dUtS62DjOfvz-QMd04mAZa\
            LkLdSxlHCYKjx6jmTQEbVFwSt_Pm1MryF7gkXg6YeiNG6EhgmLUHv50Jwt1salVH9\
            _FQVNkqiVivHNAW4cEVbuTZJl8TjtQn6MnOZSP7n8TkonrUdULoIxIl3L-kneJABB\
            aQ6zg52w00W1MXwlu-C8w\",
        \"e\":\"AQAB\",
        \"d\":\"Jb51Ytzk6_yHiD58eY9rZByzXcDnJqL5THq0xSAP3pZwlr0GWrtYlq9nfuqJF\
            duEAaZYB6yrp_cKymLvsnqrDnaD6B6uiSsJvvDusRWj4QgMoNG4gA3MpejJzHBii3\
            p7uW3zva-hLEFVM3QX8DSHMxB44G9n-Czut4ciS_MymS1LIpUk632J7VxnWOnuvVt\
            rNsWzaojINzlnnbUFDoaBHI0nm2hO22YXlnGlJBdbK-6aV1YvlR73A0Qg-NGCwv1R\
            q2pqDGCai4bEQ4vQX1sVZQWWuypMCtNY3GDlHTMXB_MWqJ3HQfDIX1LKJ1Wr0HPz8\
            W2BV7Z53i7uyea9g5RuwQ\"
        }";

    pub const SINGLE_NONCE: &str = "Nonce_1";

    pub struct MockTokenConfig {
        issuer: Url,
        client_id: String,
        pub email: Option<EndUserEmail>,
        pub name: Option<LocalizedClaim<EndUserName>>,
        pub nonce: Option<Nonce>,
        pub duration: Option<core::time::Duration>,
        pub access: String,
        pub access_for_id: String,
        pub refresh: Option<String>,
        pub signing_alg: Option<CoreJwsSigningAlgorithm>,
        pub preferred_username: Option<String>,
    }

    impl MockTokenConfig {
        pub fn create_from_tokens(
            issuer: Url,
            client_id: String,
            duration: core::time::Duration,
            access_token: String,
            refresh_token: String,
        ) -> Self {
            let mut name = LocalizedClaim::new();
            name.insert(None, EndUserName::new("Robin".to_string()));
            let name = Some(name);

            MockTokenConfig {
                issuer,
                client_id,
                email: Some(EndUserEmail::new("robin@dummy_db.com".to_string())),
                name,
                nonce: Some(Nonce::new(SINGLE_NONCE.to_string())),
                duration: Some(duration),
                access: access_token.clone(),
                access_for_id: access_token,
                refresh: Some(refresh_token),
                signing_alg: Some(CoreJwsSigningAlgorithm::RsaSsaPssSha256),
                preferred_username: None,
            }
        }
    }

    type DefaultJsonWebKeySet = openidconnect::JsonWebKeySet<CoreJsonWebKey>;

    fn mock_jwks() -> DefaultJsonWebKeySet {
        let jwk: CoreJsonWebKey =
            serde_json::from_str(TEST_JWK).expect("Parsing mock jwk should not fail");
        JsonWebKeySet::new(vec![jwk])
    }

    fn mock_token_response(
        mock_token_config: MockTokenConfig,
    ) -> StandardTokenResponse<CoreIdTokenFields, BasicTokenType> {
        let id_token = CoreIdToken::new(
            CoreIdTokenClaims::new(
                IssuerUrl::new(mock_token_config.issuer.to_string())
                    .expect("Parsing mock issuer should not fail"),
                vec![Audience::new(mock_token_config.client_id)],
                Utc::now() + Duration::seconds(300),
                Utc::now(),
                StandardClaims::new(SubjectIdentifier::new("DUMMY_SUBJECT_ID".to_string()))
                    .set_email(mock_token_config.email)
                    .set_name(mock_token_config.name)
                    .set_preferred_username(
                        mock_token_config
                            .preferred_username
                            .map(EndUserUsername::new),
                    ),
                EmptyAdditionalClaims {},
            )
            .set_nonce(mock_token_config.nonce),
            &CoreRsaPrivateSigningKey::from_pem(TEST_PRIVATE_KEY, None)
                .expect("Cannot create mock of RSA private key"),
            mock_token_config
                .signing_alg
                .unwrap_or(CoreJwsSigningAlgorithm::RsaSsaPssSha256),
            Some(&AccessToken::new(mock_token_config.access_for_id.clone())),
            None,
        )
        .expect("Cannot create mock of ID Token");

        let mut result = CoreTokenResponse::new(
            AccessToken::new(mock_token_config.access.clone()),
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );

        result.set_expires_in(mock_token_config.duration.as_ref());

        if let Some(refresh) = mock_token_config.refresh {
            result.set_refresh_token(Some(RefreshToken::new(refresh)));
        }

        result
    }

    #[tokio::test]
    async fn it_retrieves_a_new_set_of_tokens() {
        let mock_server = httptest::Server::run();
        let server_url = Url::parse(&mock_server.url_str("/"))
            .unwrap()
            .join("realms/AI4WildLIVE")
            .unwrap();

        mock_server.expect(
            Expectation::matching(all_of![
                matchers::request::method("GET"),
                matchers::request::path("/realms/AI4WildLIVE/protocol/openid-connect/certs"),
                matchers::request::headers(matchers::contains(("accept", "application/json"))),
            ])
            .respond_with(
                status_code(200)
                    .insert_header("content-type", "application/json")
                    .body(serde_json::to_string(&mock_jwks()).unwrap()),
            ),
        );

        let mut mock_token_config = MockTokenConfig::create_from_tokens(
            server_url.clone(),
            "geoengine".into(),
            std::time::Duration::from_secs(300),
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJsbkF4V0NqY2lhX3I3cFBySUtTSGd6OVhyRGxzcGY4MHUxMDJpdENoelE4In0".into(),
            "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0MWFlNzYxMC1jNzIyLTRmOWQtOGJhNi02ZTc2MmRkNDIxOWIifQ.eyJleHAiOjE3NTYxMzI5NTcsImlhdCI6MTc1NjEzMTE1NywianRpIjoiOTIwYTljM2EtMjZkMC00Y2NiLWIxYWQtNDRlNWU2NzZmZWU4IiwiaXNzIjoiaHR0cHM6Ly93ZWJhcHAuc2VuY2tlbmJlcmcuZGUvYXV0aC9yZWFsbXMvd2lsZGxpdmUtcG9ydGFsIiwiYXVkIjoiaHR0cHM6Ly93ZWJhcHAuc2VuY2tlbmJlcmcuZGUvYXV0aC9yZWFsbXMvd2lsZGxpdmUtcG9ydGFsIiwic3ViIjoiMmRhZDgxZGYtOTVhZS00Y2E4LWE4NTktZWQyZjM0OWRlOWY2IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6IndpbGRsaXZlLWZyb250ZW5kIiwic2Vzc2lvbl9zdGF0ZSI6ImFhNjljMDkzLTQ4YTUtNDg1Zi1iMWZkLTQ4MTE4YmY2YmI1NSIsInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6ImFhNjljMDkzLTQ4YTUtNDg1Zi1iMWZkLTQ4MTE4YmY2YmI1NSJ9.COoMWxp6IZ_IKTQ-GGAb22CIcybY32II5wn9beaSoyw".into(),
        );
        mock_token_config.signing_alg = Some(CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256);
        mock_token_config.preferred_username = Some("testuser".into());
        let token_response = mock_token_response(mock_token_config);

        let mut token_response_json = serde_json::to_value(&token_response).unwrap();
        token_response_json["refresh_expires_in"] = serde_json::json!(300);

        mock_server.expect(
            Expectation::matching(all_of![
                matchers::request::method("POST"),
                matchers::request::path("/realms/AI4WildLIVE/protocol/openid-connect/token"),
                matchers::request::headers(matchers::contains(("accept", "application/json"))),
            ])
            .respond_with(
                status_code(200)
                    .insert_header("content-type", "application/json")
                    .body(token_response_json.to_string()),
            ),
        );
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let jwks = retrieve_jwks(&http_client, &server_url.clone())
            .await
            .unwrap();

        let refresh_token = RefreshToken::new("eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0MWFlNzYxMC1jNzIyLTRmOWQtOGJhNi02ZTc2MmRkNDIxOWIifQ.eyJleHAiOjE3NTYxMzI5NTcsImlhdCI6MTc1NjEzMTE1NywianRpIjoiOTIwYTljM2EtMjZkMC00Y2NiLWIxYWQtNDRlNWU2NzZmZWU4IiwiaXNzIjoiaHR0cHM6Ly93ZWJhcHAuc2VuY2tlbmJlcmcuZGUvYXV0aC9yZWFsbXMvd2lsZGxpdmUtcG9ydGFsIiwiYXVkIjoiaHR0cHM6Ly93ZWJhcHAuc2VuY2tlbmJlcmcuZGUvYXV0aC9yZWFsbXMvd2lsZGxpdmUtcG9ydGFsIiwic3ViIjoiMmRhZDgxZGYtOTVhZS00Y2E4LWE4NTktZWQyZjM0OWRlOWY2IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6IndpbGRsaXZlLWZyb250ZW5kIiwic2Vzc2lvbl9zdGF0ZSI6ImFhNjljMDkzLTQ4YTUtNDg1Zi1iMWZkLTQ4MTE4YmY2YmI1NSIsInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6ImFhNjljMDkzLTQ4YTUtNDg1Zi1iMWZkLTQ4MTE4YmY2YmI1NSJ9.COoMWxp6IZ_IKTQ-GGAb22CIcybY32II5wn9beaSoyw".into());
        let response = retrieve_access_and_refresh_token(
            &http_client,
            &crate::config::Oidc {
                issuer: server_url.clone(),
                client_id: "geoengine".into(),
                client_secret: None,
            },
            jwks,
            &refresh_token,
        )
        .await
        .unwrap();

        assert!(!response.refresh_token.secret().is_empty());
        assert!(response.user.is_some());
    }
}
