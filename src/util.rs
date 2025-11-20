use url::Url;

pub fn join_base_url_and_path(base_url: &Url, path: &str) -> Result<Url, url::ParseError> {
    let mut url = base_url.to_string();

    if !url.ends_with('/') {
        url.push('/');
    }

    if let Some(stripped) = path.strip_prefix('/') {
        url.push_str(stripped);
    } else {
        url.push_str(path);
    }

    url.parse()
}
