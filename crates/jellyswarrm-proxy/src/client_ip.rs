//! Best-effort client IP extraction for rate limiting the login endpoint.
//!
//! This proxy is only ever exposed via a reverse proxy (Caddy) on the docker
//! network -- see `compose.yml`, which uses `expose:` rather than publishing
//! a host port -- so the immediate TCP peer is always the trusted reverse
//! proxy, and `X-Forwarded-For`'s left-most entry (the original client, per
//! the usual convention) is safe to trust here. This is a simplifying
//! assumption for a single-reverse-proxy homelab deployment, not a general
//! trusted-proxy-chain implementation; it does not attempt to validate how
//! many hops the header claims or guard against a client on the same docker
//! network forging it.

use hyper::HeaderMap;

pub fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn extracts_the_left_most_forwarded_for_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.5, 10.0.0.1, 10.0.0.2"),
        );
        assert_eq!(extract_client_ip(&headers), "203.0.113.5");
    }

    #[test]
    fn falls_back_to_unknown_when_header_absent() {
        let headers = HeaderMap::new();
        assert_eq!(extract_client_ip(&headers), "unknown");
    }
}
