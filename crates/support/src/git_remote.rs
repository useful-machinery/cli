/// A Git remote address read as the host it names and the repository's path on that host.
///
/// The user information an address may carry, which can hold a credential, is never part of
/// either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteAddress<'a> {
    /// The host, without user information or port.
    pub host: &'a str,
    /// The path on the host without a leading `/`, a trailing `/` or a trailing `.git`; empty
    /// when the address names a host alone.
    pub path: &'a str,
}

/// Reads a Git remote address, `scheme://[userinfo@]host[:port]/path` or the scp form
/// `[user@]host:path`, as its host and path. An address that names no host, such as a local
/// path, is `None`.
pub fn remote_address(address: &str) -> Option<RemoteAddress<'_>> {
    let (host, path) = if let Some((_, rest)) = address.split_once("://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host_and_port = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let host = host_and_port.split(':').next().unwrap_or_default();
        (host, path)
    } else {
        let (prefix, path) = address.split_once(':')?;
        if prefix.contains('/') {
            return None;
        }
        (
            prefix.rsplit_once('@').map_or(prefix, |(_, host)| host),
            path,
        )
    };
    if host.is_empty() {
        return None;
    }
    let path = path.trim_start_matches('/').trim_end_matches('/');
    Some(RemoteAddress {
        host,
        path: path.strip_suffix(".git").unwrap_or(path),
    })
}
