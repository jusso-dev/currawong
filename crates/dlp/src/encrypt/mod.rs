//! Message encryption for the `encrypt`, `encrypt_smime` and `encrypt_portal`
//! policy actions. PGP is out of scope.
pub mod portal;
#[cfg(feature = "smime")]
pub mod smime;

pub use portal::{code_mail, notice, Issued, PortalError, PortalStore, Route};

/// Header fields and body of a message, split at the first empty line.
/// Each field keeps its folded continuation lines and its line ending.
pub(crate) fn split_message(raw: &[u8]) -> (Vec<&[u8]>, &[u8]) {
    let mut fields: Vec<&[u8]> = Vec::new();
    let mut pos = 0;
    let mut start = None;
    while pos < raw.len() {
        let end = raw[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(raw.len(), |i| pos + i + 1);
        let line = &raw[pos..end];
        if line == b"\r\n" || line == b"\n" {
            if let Some(s) = start {
                fields.push(&raw[s..pos]);
            }
            return (fields, &raw[end..]);
        }
        if !line.starts_with(b" ") && !line.starts_with(b"\t") {
            if let Some(s) = start {
                fields.push(&raw[s..pos]);
            }
            start = Some(pos);
        }
        pos = end;
    }
    // No empty line: everything is header.
    if let Some(s) = start {
        fields.push(&raw[s..]);
    }
    (fields, &[])
}

/// The field name, lower case.
pub(crate) fn field_name(field: &[u8]) -> String {
    let name = field.split(|&b| b == b':').next().unwrap_or_default();
    String::from_utf8_lossy(name).trim().to_ascii_lowercase()
}

/// Unfolded field value, for the few fields read here (`From`).
pub(crate) fn field_value(fields: &[&[u8]], name: &str) -> Option<String> {
    let field = fields.iter().find(|f| field_name(f) == name)?;
    let text = String::from_utf8_lossy(field);
    let value = text.split_once(':').map(|(_, v)| v).unwrap_or_default();
    Some(value.split_whitespace().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_split_keeps_folded_fields_together() {
        let raw = b"From: a@example.com.au\r\nSubject: one\r\n two\r\n\r\nbody\r\n";
        let (fields, body) = split_message(raw);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1], b"Subject: one\r\n two\r\n");
        assert_eq!(body, b"body\r\n");
        assert_eq!(field_value(&fields, "subject").unwrap(), "one two");
        let (fields, body) = split_message(b"Subject: x\r\n");
        assert_eq!((fields.len(), body.len()), (1, 0));
    }
}
