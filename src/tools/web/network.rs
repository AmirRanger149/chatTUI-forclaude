//! A direct, credential-free transport for public HTTPS. The
//! chat-provider client is deliberately not used here (different trust boundary).

use anyhow::{anyhow, bail, ensure, Result};
use reqwest::{header, Client, Response};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use url::{Host, Url};

pub(super) const MAX_BODY: usize = 512 * 1024;
pub(super) const DEADLINE: Duration = Duration::from_secs(15);
const MAX_URL: usize = 2048;

pub(super) fn public_url(raw: &str) -> Result<Url> {
    ensure!(
        raw.len() <= MAX_URL
            && !raw
                .chars()
                .any(|c| c.is_whitespace() || super::unsafe_char(c) || c == '\\'),
        "invalid or oversized web URL"
    );
    let mut url = Url::parse(raw).map_err(|_| anyhow!("expected an absolute public HTTPS URL"))?;
    ensure!(
        url.scheme() == "https" && url.port_or_known_default() == Some(443),
        "only HTTPS on port 443 is allowed"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "credentials in URLs are not allowed"
    );
    // Only fully qualified DNS names, not IP literals, single-label names,
    // or names that the system resolver might route to local services/mDNS.
    let Some(Host::Domain(host)) = url.host() else {
        bail!("expected a public DNS hostname, not an IP address");
    };
    ensure!(
        host.len() <= 253
            && host.contains('.')
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
            && ![
                "localhost",
                "local",
                "internal",
                "lan",
                "arpa",
                "onion",
                "test",
                "invalid"
            ]
            .contains(&host.rsplit('.').next().unwrap_or("")),
        "local or invalid hostname is not allowed"
    );
    url.set_fragment(None); // Never sent over HTTP; approve the actual URL.
    ensure!(url.as_str().len() <= MAX_URL, "encoded web URL is too long");
    Ok(url)
}

/// Conservatively admit ordinary public unicast addresses only. In particular
/// IPv4-mapped IPv6, NAT64, Teredo and 6to4 must not smuggle a private IPv4
/// destination through the IPv6 check.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && !matches!(
                    ip.octets(),
                    [0 | 224..=255, ..]
                        | [100, 64..=127, ..]
                        | [192, 0, 0, _]
                        | [192, 88, 99, _]
                        | [198, 18..=19, ..]
                        | [168, 63, 129, 16]
                )
        }
        IpAddr::V6(ip) => {
            let [a, b, _, _, _, _, _, _] = ip.segments();
            (a & 0xe000) == 0x2000
                && a != 0x2002
                && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                && !(a == 0x3fff && b < 0x1000)
        }
    }
}

fn checked_addrs(addrs: impl Iterator<Item = SocketAddr>) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = addrs.collect();
    ensure!(
        !addrs.is_empty() && addrs.iter().all(|a| public_ip(a.ip())),
        "DNS returned an empty answer or a non-public address"
    );
    Ok(addrs)
}

/// Resolve once per hop, reject the *entire* answer set on any non-public
/// address, and give TLS/HTTP exactly those IPs while retaining the original
/// hostname for certificate verification and SNI. No second DNS lookup or
/// implicit proxy re-resolution is allowed between the check and connect.
async fn client_for(url: &Url) -> Result<Client> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing HTTPS hostname"))?;
    let fqdn = format!("{host}."); // no resolver search-domain expansion
    let addresses = checked_addrs(
        tokio::net::lookup_host((fqdn.as_str(), 443))
            .await
            .map_err(|_| anyhow!("could not resolve the HTTPS hostname"))?,
    )?;
    Ok(Client::builder()
        .https_only(true)
        .no_proxy()
        .referer(false)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .resolve_to_addrs(host, &addresses)
        .connect_timeout(Duration::from_secs(5))
        .timeout(DEADLINE)
        .user_agent(concat!("chatTUI/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// A single pinned GET; callers control whether a redirect can be followed.
pub(super) async fn get(url: Url, accept: &'static str) -> Result<Response> {
    client_for(&url)
        .await?
        .get(url)
        .header(header::ACCEPT, accept)
        .header(header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(send_error)
}

// reqwest errors carry the URL; a query string may be sensitive. Keep the
// source chain available for diagnostics, but give the chat a useful, safe
// top-level message instead of an opaque "error sending request".
fn send_error(error: reqwest::Error) -> anyhow::Error {
    let message = if error.is_timeout() {
        "web request timed out"
    } else if error.is_connect() {
        "web connection failed; check direct HTTPS access and the site's TLS certificate"
    } else {
        "could not send the HTTPS request"
    };
    anyhow::Error::new(error.without_url()).context(message)
}

pub(super) async fn body(mut response: Response) -> Result<Vec<u8>> {
    ensure!(
        response
            .headers()
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .all(|v| v.as_bytes().eq_ignore_ascii_case(b"identity")),
        "compressed web responses are not supported"
    );
    ensure!(
        response.content_length().unwrap_or(0) <= MAX_BODY as u64,
        "web response exceeds 512 KiB"
    );
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url())? {
        ensure!(
            data.len().saturating_add(chunk.len()) <= MAX_BODY,
            "web response exceeds 512 KiB"
        );
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_https_names_are_candidates_for_dns() {
        for url in [
            "/relative",
            "file:///a",
            "http://site.com",
            "https://a:b@site.com",
            "https://site.com:444/",
            "https://localhost/",
            "https://foo.local/",
            "https://site.com./",
            "https://127.0.0.1",
            "https://[::1]",
            "https://2130706433",
            "https://site.com/\nfoo",
            "https://site.com/a\u{202e}b",
        ] {
            assert!(public_url(url).is_err(), "{url:?}");
        }
        assert_eq!(
            public_url("https://DOCS.rs:443/a?q=b#section")
                .unwrap()
                .as_str(),
            "https://docs.rs/a?q=b"
        );
    }

    #[test]
    fn rejects_special_and_mixed_dns_answers() {
        for addr in [
            "0.1.2.3",
            "100.64.0.1",
            "10.0.0.2",
            "169.254.169.254",
            "127.1.2.3",
            "192.0.0.9",
            "198.19.0.1",
            "192.0.2.1",
            "224.1.2.3",
            "240.0.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002::1",
            "2001::1",
            "3fff::1",
        ] {
            assert!(!public_ip(addr.parse().unwrap()), "{addr}");
        }
        let public = "1.1.1.1:443".parse().unwrap();
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(checked_addrs([public].into_iter()).is_ok());
        assert!(checked_addrs([public, "[::1]:443".parse().unwrap()].into_iter()).is_err());
        assert!(checked_addrs(std::iter::empty()).is_err());
    }
}
