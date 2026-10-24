//! Offline wrapper decoding. Unknown and opaque formats stay wrapped.
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use url::Url;

fn parameter(url: &Url, names: &[&str]) -> Result<Option<String>, String> {
    let values: Vec<_> = url
        .query_pairs()
        .filter(|(k, _)| names.contains(&k.as_ref()))
        .map(|(_, v)| v.into_owned())
        .collect();
    if values.len() > 1 {
        return Err("ambiguous wrapper parameters".into());
    }
    Ok(values.into_iter().next())
}
fn b64(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|_| "invalid wrapper base64".into())
}
fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|n| n as u8)
}
fn v2(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                out.push(b'/');
                i += 1;
            }
            b'-' if i + 2 < bytes.len()
                && hex(bytes[i + 1]).is_some()
                && hex(bytes[i + 2]).is_some() =>
            {
                out.push(hex(bytes[i + 1]).unwrap() * 16 + hex(bytes[i + 2]).unwrap());
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "invalid wrapper UTF-8".into())
}
fn v3(url: &Url) -> Result<String, String> {
    let (_, tail) = url
        .as_str()
        .split_once("/v3/__")
        .ok_or("invalid Proofpoint v3 wrapper")?;
    let (target, suffix) = tail
        .rsplit_once("__;")
        .ok_or("invalid Proofpoint v3 terminator")?;
    let encoded = suffix.split('!').next().unwrap_or("");
    let map = b64(encoded)?;
    let mut mapped = 0;
    let mut out = Vec::new();
    let bytes = target.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'*' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let count = if bytes.get(i + 1) == Some(&b'*') {
            let code = *bytes.get(i + 2).ok_or("invalid Proofpoint run")?;
            i += 3;
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                .iter()
                .position(|c| *c == code)
                .ok_or("invalid Proofpoint run")?
                + 2
        } else {
            i += 1;
            1
        };
        let end = mapped + count;
        out.extend_from_slice(
            map.get(mapped..end)
                .ok_or("short Proofpoint character map")?,
        );
        mapped = end;
    }
    if mapped != map.len() {
        return Err("unused Proofpoint character map".into());
    }
    String::from_utf8(out).map_err(|_| "invalid Proofpoint UTF-8".into())
}
/// One hop only. Caller budgets and checks every intermediate URL.
pub fn unwrap(url: &Url, generic: &[String]) -> Result<Option<Url>, String> {
    let host = url.host_str().unwrap_or("").trim_end_matches('.');
    let target = if matches!(host, "google.com" | "www.google.com") && url.path() == "/url" {
        parameter(url, &["q", "url"])?
    } else if crate::host_matches(host, "safelinks.protection.outlook.com") {
        parameter(url, &["url"])?
    } else if matches!(host, "urldefense.proofpoint.com" | "urldefense.com")
        && url.path() == "/v2/url"
    {
        parameter(url, &["u"])?.map(|u| v2(&u)).transpose()?
    } else if matches!(host, "urldefense.proofpoint.com" | "urldefense.com")
        && url.path().starts_with("/v3/__")
    {
        Some(v3(url)?)
    } else if host == "l.facebook.com" && url.path() == "/l.php" {
        parameter(url, &["u"])?
    } else if matches!(host, "bing.com" | "www.bing.com") && url.path() == "/ck/a" {
        parameter(url, &["u"])?
            .map(|u| {
                let encoded = u.strip_prefix("a1").ok_or("unknown Bing encoding")?;
                String::from_utf8(b64(encoded)?).map_err(|_| "invalid Bing UTF-8".to_string())
            })
            .transpose()?
    } else if (host.starts_with("protect-")
        && host.ends_with(".mimecast.com")
        && host.split('.').count() == 3)
        || generic.iter().any(|d| host.eq_ignore_ascii_case(d))
    {
        // Current Mimecast /s/<opaque token> has no offline destination.
        parameter(url, &["url", "u"])?
    } else {
        None
    };
    target
        .map(|t| {
            let target = Url::parse(&t).map_err(|_| "wrapper target is not an absolute URL")?;
            if !matches!(target.scheme(), "http" | "https")
                || target.host_str().is_none()
                || !target.username().is_empty()
                || target.password().is_some()
            {
                return Err("unsafe wrapper target".into());
            }
            Ok(target)
        })
        .transpose()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn each_wrapper_and_exact_host_boundaries() {
        for raw in [
            "https://www.google.com/url?q=https%3A%2F%2Fexample.com%2Fx",
            "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fx",
            "https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_x&d=other",
            "https://urldefense.com/v3/__https://example.com/x__;!id!sig$",
            "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com%2Fx",
            "https://www.bing.com/ck/a?u=a1aHR0cHM6Ly9leGFtcGxlLmNvbS94",
            "https://protect-au.mimecast.com/?url=https%3A%2F%2Fexample.com%2Fx",
            "https://redirect.test/?u=https%3A%2F%2Fexample.com%2Fx",
        ] {
            assert_eq!(
                unwrap(&Url::parse(raw).unwrap(), &["redirect.test".into()])
                    .unwrap()
                    .unwrap()
                    .as_str(),
                "https://example.com/x",
                "{raw}"
            );
        }
        for raw in [
            "https://google.com.evil.test/url?q=https://example.com/",
            "https://unknown.test/?url=https://example.com/",
            "https://protect-au.mimecast.com/s/opaque-token",
        ] {
            assert!(unwrap(&Url::parse(raw).unwrap(), &[]).unwrap().is_none());
        }
        for raw in [
            "https://google.com/url?q=javascript:alert(1)",
            "https://google.com/url?q=https://a.test/&q=https://b.test/",
            "https://www.bing.com/ck/a?u=bad",
        ] {
            assert!(unwrap(&Url::parse(raw).unwrap(), &[]).is_err());
        }
    }
    #[test]
    fn proofpoint_documented_v3_map_and_v2_escapes() {
        let raw = "https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg!sig$";
        assert_eq!(
            unwrap(&Url::parse(raw).unwrap(), &[])
                .unwrap()
                .unwrap()
                .as_str(),
            "https://google.com/search?q=a+test&gs=ps"
        );
        assert_eq!(
            v2("https-3A__example.com_a-5Fb-2Dc").unwrap(),
            "https://example.com/a_b-c"
        );
        let raw = "https://urldefense.com/v3/__https://example.com/**A__;KyY!id!sig$";
        assert_eq!(
            unwrap(&Url::parse(raw).unwrap(), &[])
                .unwrap()
                .unwrap()
                .as_str(),
            "https://example.com/+&"
        );
    }
}
