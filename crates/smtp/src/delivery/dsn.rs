//! RFC 3464 delivery status notifications in an RFC 6522 multipart/report.
//! Never addressed to the null sender.
use super::client::sanitise;
use currawong_spool::{Envelope, RcptStatus};
use mail_builder::{
    headers::{content_type::ContentType, text::Text},
    mime::{BodyPart, MimePart},
    MessageBuilder,
};

/// Build a DSN for `failed`, the recipients being bounced in this report.
pub fn build_dsn(
    hostname: &str,
    env: &Envelope,
    original: &[u8],
    failed: &[RcptStatus],
) -> Vec<u8> {
    let recipients = failed
        .iter()
        .map(|status| {
            format!(
                "\r\nFinal-Recipient: rfc822; {}\r\nAction: failed\r\nStatus: {}\r\nDiagnostic-Code: smtp; {}\r\n",
                field(&status.address),
                status_code(&status.detail),
                field(&status.detail)
            )
        })
        .collect::<String>();
    let report = format!("Reporting-MTA: dns; {hostname}\r\n{recipients}");
    let explanation = format!(
        "Delivery to the following recipients failed permanently:\r\n\r\n{}\r\n",
        failed
            .iter()
            .map(|status| format!(
                "  {}: {}\r\n",
                sanitise(&status.address),
                sanitise(&status.detail)
            ))
            .collect::<String>()
    );
    let returned = String::from_utf8_lossy(&header_block(original)).into_owned();
    let daemon = format!("mailer-daemon@{hostname}");
    MessageBuilder::new()
        .from(("Mail Delivery Subsystem", daemon.as_str()))
        .to(env.mail_from.as_str())
        .subject("Delivery Status Notification (Failure)")
        .header("Auto-Submitted", Text::new("auto-generated"))
        .header("X-Currawong-DSN", Text::new("1"))
        .body(MimePart::new(
            ContentType::new("multipart/report").attribute("report-type", "delivery-status"),
            BodyPart::Multipart(vec![
                MimePart::new(
                    ContentType::new("text/plain").attribute("charset", "utf-8"),
                    BodyPart::Text(explanation.into()),
                ),
                MimePart::new(
                    ContentType::new("message/delivery-status"),
                    BodyPart::Text(report.into()),
                )
                .transfer_encoding("7bit"),
                MimePart::new(
                    ContentType::new("text/rfc822-headers"),
                    BodyPart::Text(returned.into()),
                ),
            ]),
        ))
        .write_to_vec()
        .unwrap_or_else(|_| fallback_dsn(hostname, env))
}

/// One delivery-status field value: printable ASCII, well under 998 octets,
/// so the part can go out as 7bit without encoding.
fn field(value: &str) -> String {
    sanitise(value)
        .chars()
        .map(|ch| if ch.is_ascii() { ch } else { '?' })
        .take(900)
        .collect()
}

/// The RFC 3463 code from a reply such as `550 5.1.1 no such user`, else the
/// class of the basic code, else 5.0.0.
pub fn status_code(detail: &str) -> String {
    let mut words = detail.split_whitespace();
    let mut basic = None;
    for word in words.by_ref().take(2) {
        if is_enhanced(word) {
            return word.to_string();
        }
        if word.len() == 3 && word.bytes().all(|b| b.is_ascii_digit()) && basic.is_none() {
            basic = Some(word[..1].to_string());
            continue;
        }
        break;
    }
    match basic.as_deref() {
        Some(class @ ("4" | "5")) => format!("{class}.0.0"),
        _ => "5.0.0".into(),
    }
}

fn is_enhanced(word: &str) -> bool {
    let parts: Vec<&str> = word.split('.').collect();
    parts.len() == 3
        && matches!(parts[0], "2" | "4" | "5")
        && parts[1..]
            .iter()
            .all(|part| (1..=3).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()))
}

fn header_block(original: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in original.split(|&b| b == b'\n') {
        if line.is_empty() || line == b"\r" {
            break;
        }
        out.extend_from_slice(line);
        out.push(b'\n');
        if out.len() > 64 * 1024 {
            break;
        }
    }
    out
}

fn fallback_dsn(hostname: &str, env: &Envelope) -> Vec<u8> {
    format!(
        "From: Mail Delivery Subsystem <mailer-daemon@{hostname}>\r\n\
         To: {to}\r\n\
         Subject: Delivery Status Notification (Failure)\r\n\
         Auto-Submitted: auto-generated\r\n\
         X-Currawong-DSN: 1\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         Delivery failed permanently.\r\n",
        to = sanitise(&env.mail_from)
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_from_reply() {
        assert_eq!(status_code("550 5.1.1 no such user"), "5.1.1");
        assert_eq!(status_code("550 no such user"), "5.0.0");
        assert_eq!(status_code("452 too many"), "4.0.0");
        assert_eq!(status_code("4.4.7 message expired"), "4.4.7");
        assert_eq!(status_code("connect refused"), "5.0.0");
    }
}
