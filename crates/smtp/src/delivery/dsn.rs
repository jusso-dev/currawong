//! RFC 3464 delivery status notifications. Never addressed to the null sender.
use currawong_spool::Envelope;
use mail_builder::headers::text::Text;
use mail_builder::MessageBuilder;

pub fn build_dsn(hostname: &str, env: &Envelope, original: &[u8], detail: &str) -> Vec<u8> {
    let recipients = env
        .rcpt_status
        .iter()
        .filter(|status| status.status == "perm")
        .map(|status| format!("Final-Recipient: rfc822; {}\r\nAction: failed\r\nStatus: 5.0.0\r\nDiagnostic-Code: smtp; {}\r\n", status.address, status.detail))
        .collect::<String>();
    let status = format!("Reporting-MTA: dns; {hostname}\r\n{recipients}");
    let explanation =
        format!("Delivery to one or more recipients failed permanently.\r\n\r\n{detail}\r\n");
    let returned = header_block(original);
    MessageBuilder::new()
        .from(format!(
            "Mail Delivery Subsystem <mailer-daemon@{hostname}>"
        ))
        .to(env.mail_from.as_str())
        .subject("Delivery Status Notification (Failure)")
        .header("Auto-Submitted", Text::new("auto-replied"))
        .header("X-Currawong-DSN", Text::new("1"))
        .text_body(explanation)
        .attachment(
            "message/delivery-status",
            "delivery-status",
            status.into_bytes(),
        )
        .attachment("text/rfc822-headers", "returned-headers", returned)
        .write_to_vec()
        .unwrap_or_else(|_| fallback_dsn(hostname, env, detail))
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

fn fallback_dsn(hostname: &str, env: &Envelope, detail: &str) -> Vec<u8> {
    format!(
        "From: Mail Delivery Subsystem <mailer-daemon@{hostname}>\r\n\
         To: {to}\r\n\
         Subject: Delivery Status Notification (Failure)\r\n\
         Auto-Submitted: auto-replied\r\n\
         X-Currawong-DSN: 1\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         Delivery failed permanently.\r\n\
         {detail}\r\n",
        to = env.mail_from
    )
    .into_bytes()
}
