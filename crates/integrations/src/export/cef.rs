//! ArcSight Common Event Format (CEF) version 0.
use super::event::{Event, EventKind};

const VENDOR: &str = "Currawong";
const PRODUCT: &str = "Currawong Gateway";

/// One CEF line, without a trailing newline.
pub fn format(event: &Event) -> String {
    let (name, ext) = extension(event);
    let mut out = format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|",
        header(VENDOR),
        header(PRODUCT),
        header(env!("CARGO_PKG_VERSION")),
        header(event.type_name()),
        header(name),
        event.severity()
    );
    let mut first = true;
    for (key, value) in ext {
        if !first {
            out.push(' ');
        }
        first = false;
        out.push_str(key);
        out.push('=');
        out.push_str(&value_escape(&value));
    }
    out
}

fn extension(event: &Event) -> (&'static str, Vec<(&'static str, String)>) {
    let mut ext = vec![
        ("rt", event.unix_millis().to_string()),
        ("externalId", event.id.clone()),
    ];
    if let Some(tenant) = &event.tenant_id {
        ext.push(("cs1Label", "tenant".into()));
        ext.push(("cs1", tenant.clone()));
    }
    let message = |ext: &mut Vec<(&'static str, String)>, id: &str| {
        ext.push(("cs2Label", "messageId".into()));
        ext.push(("cs2", id.into()));
    };
    let name = match &event.kind {
        EventKind::MessageVerdict {
            message_id,
            direction,
            mail_from,
            rcpt_to,
            verdict,
            reason,
        } => {
            message(&mut ext, message_id);
            ext.push(("act", verdict.clone()));
            ext.push(("suser", mail_from.clone()));
            ext.push(("duser", rcpt_to.join(",")));
            let dir = if direction == "outbound" { "1" } else { "0" };
            ext.push(("deviceDirection", dir.into()));
            if let Some(reason) = reason {
                ext.push(("reason", reason.clone()));
            }
            "Message verdict"
        }
        EventKind::UrlClick {
            message_id,
            recipient,
            url,
            action,
        } => {
            message(&mut ext, message_id);
            ext.push(("act", action.clone()));
            ext.push(("duser", recipient.clone()));
            ext.push(("request", url.clone()));
            "URL click"
        }
        EventKind::QuarantineRelease {
            message_id,
            released_by,
            rcpt_to,
        } => {
            message(&mut ext, message_id);
            ext.push(("act", "release".into()));
            ext.push(("suser", released_by.clone()));
            ext.push(("duser", rcpt_to.join(",")));
            "Quarantine release"
        }
        EventKind::AdminAction {
            actor,
            action,
            target,
        } => {
            ext.push(("act", action.clone()));
            ext.push(("suser", actor.clone()));
            ext.push(("cs3Label", "target".into()));
            ext.push(("cs3", target.clone()));
            "Admin action"
        }
        EventKind::VerdictChanged {
            message_id,
            from,
            to,
            changed_by,
        } => {
            message(&mut ext, message_id);
            ext.push(("act", to.clone()));
            ext.push(("suser", changed_by.clone()));
            ext.push(("cs4Label", "previousVerdict".into()));
            ext.push(("cs4", from.clone()));
            "Verdict changed"
        }
    };
    (name, ext)
}

/// Header fields escape `\` and `|`. Line breaks are not allowed, so they become spaces.
pub fn header(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\r' | '\n' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

/// Extension values escape `\` and `=`, and encode line breaks as `\n` and `\r`.
pub fn value_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::event::tests::samples;
    use std::path::PathBuf;

    fn golden_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/cef")
    }

    /// `CURRAWONG_BLESS=1` rewrites the golden files. Review the diff before committing.
    #[test]
    fn cef_matches_golden_files() {
        for event in samples() {
            let path = golden_dir().join(format!("{}.cef", event.type_name()));
            if std::env::var_os("CURRAWONG_BLESS").is_some() {
                std::fs::write(&path, format!("{}\n", format(&event))).unwrap();
            }
            let expected = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            assert_eq!(format(&event), expected.trim_end_matches('\n'), "{path:?}");
        }
    }

    #[test]
    fn cef_escapes_pipe_backslash_and_equals() {
        assert_eq!(header(r"a|b\c=d"), r"a\|b\\c=d");
        assert_eq!(value_escape("a|b\\c=d\ne"), r"a|b\\c\=d\ne");
        assert_eq!(header("x\ny"), "x y");
    }
}
