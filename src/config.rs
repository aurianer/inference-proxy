use std::io::Read;

use zeroize::Zeroizing;

pub const MIN_KEY_LEN: usize = 32;
const MAX_STDIN: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Auth {
    Bearer,
    XApiKey,
}

#[derive(Debug, PartialEq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    pub base_path: String,
}

impl Upstream {
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub struct Args {
    pub upstream: Upstream,
    /// 0 lets the kernel pick a free port.
    pub port: u16,
    pub auth: Auth,
}

pub struct Secrets {
    pub key: Zeroizing<String>,
    pub token: Zeroizing<String>,
}

pub fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut upstream, mut port, mut auth) = (None, None, Auth::Bearer);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--upstream" => upstream = Some(parse_upstream(&value)?),
            "--port" => port = Some(value.parse().map_err(|_| "--port must be 0-65535")?),
            "--auth" => {
                auth = match value.as_str() {
                    "bearer" => Auth::Bearer,
                    "x-api-key" => Auth::XApiKey,
                    _ => return Err("--auth must be bearer or x-api-key".into()),
                }
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    Ok(Args {
        upstream: upstream.ok_or("--upstream is required")?,
        port: port.unwrap_or(0),
        auth,
    })
}

pub fn parse_upstream(url: &str) -> Result<Upstream, String> {
    let rest = url.strip_prefix("https://").ok_or("--upstream must be an https:// URL")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    if path.contains(['?', '#']) {
        return Err("--upstream must not contain a query or fragment".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "--upstream has an invalid port")?),
        None => (authority, 443),
    };
    let base_path = path.trim_end_matches('/');
    if port == 0 || (!base_path.is_empty() && !is_clean_path(base_path)) {
        return Err("--upstream has an invalid port or base path".into());
    }
    let host_ok = !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !host_ok {
        return Err("--upstream needs a plain host name, without credentials".into());
    }
    Ok(Upstream {
        host: host.to_ascii_lowercase(),
        port,
        base_path: base_path.to_string(),
    })
}

/// Absolute path of non-empty segments made of [A-Za-z0-9_.-], without "." or ".." segments.
/// Leaves nothing (encodings, ";" parameters, "//") an upstream could normalise differently.
pub fn is_clean_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else { return false };
    rest.split('/').all(|seg| {
        !seg.is_empty()
            && seg != "."
            && seg != ".."
            && seg.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    })
}

/// Printable ASCII without spaces: rules out header injection through CR/LF.
pub fn is_header_safe(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| (33..=126).contains(&b))
}

pub fn read_secrets(input: impl Read) -> Result<Secrets, String> {
    let mut data = Zeroizing::new(Vec::with_capacity(MAX_STDIN + 1));
    input
        .take(MAX_STDIN as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    if data.len() > MAX_STDIN {
        return Err("stdin too large".into());
    }
    let text = std::str::from_utf8(&data).map_err(|_| "stdin is not valid UTF-8")?;
    let mut lines = text.split('\n');
    let key = lines.next().unwrap_or("").trim();
    let token = lines.next().unwrap_or("").trim();
    if key.len() < MIN_KEY_LEN || !is_header_safe(key) {
        return Err(format!("local key must be >= {MIN_KEY_LEN} printable characters"));
    }
    if !is_header_safe(token) {
        return Err("token missing or contains invalid characters".into());
    }
    Ok(Secrets {
        key: Zeroizing::new(key.to_string()),
        token: Zeroizing::new(token.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_with_port_and_path() {
        let u = parse_upstream("https://GW.example.ch:8443/base/").unwrap();
        assert_eq!(u, Upstream { host: "gw.example.ch".into(), port: 8443, base_path: "/base".into() });
        assert_eq!(u.host_header(), "gw.example.ch:8443");
    }

    #[test]
    fn upstream_rejects_unsafe_forms() {
        for url in [
            "http://a.ch",
            "https://user:pw@a.ch",
            "https://a.ch/x?y=1",
            "https://",
            "https://[::1]",
            "https://a.ch:99999",
            "https://a.ch:0",
            "https://a.ch/a/../b",
            "https://a.ch/a b",
        ] {
            assert!(parse_upstream(url).is_err(), "{url}");
        }
    }

    #[test]
    fn clean_paths() {
        assert!(is_clean_path("/v1/messages"));
        assert!(is_clean_path("/v1/models/glm-5.3"));
        for p in ["", "v1", "/", "/v1/", "/v1//x", "/v1/./x", "/v1/../x", "/v1/..;/x", "/v1/%2e/x"] {
            assert!(!is_clean_path(p), "{p}");
        }
    }

    #[test]
    fn secrets_ignore_extra_lines() {
        let key = "k".repeat(MIN_KEY_LEN);
        let s = read_secrets(format!("{key}\ntok\nnote\n").as_bytes()).unwrap();
        assert_eq!(s.key.as_str(), key);
        assert_eq!(s.token.as_str(), "tok");
    }

    #[test]
    fn secrets_reject_short_key_and_missing_token() {
        assert!(read_secrets("short\ntok\n".as_bytes()).is_err());
        let key = "k".repeat(MIN_KEY_LEN);
        assert!(read_secrets(format!("{key}\n").as_bytes()).is_err());
        assert!(read_secrets(format!("{key}\nbad token\n").as_bytes()).is_err());
    }
}
