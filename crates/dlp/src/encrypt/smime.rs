//! S/MIME enveloped-data (RFC 8551, RFC 5652): the message content goes in
//! an `application/pkcs7-mime` part, encrypted with AES-256-CBC under a
//! random key that is wrapped with each recipient's RSA public key. The
//! routing headers stay readable; `Content-*` headers move inside.
//!
//! Uses the pure Rust `cms` crate rather than OpenSSL's `Pkcs7::encrypt`, so
//! the gateway does not link a system OpenSSL.
use super::{field_name, split_message};
use base64::Engine;
use cms::{
    builder::{
        ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
        KeyTransRecipientInfoBuilder,
    },
    cert::IssuerAndSerialNumber,
    content_info::ContentInfo,
    enveloped_data::RecipientIdentifier,
};
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use std::path::Path;
use x509_cert::{
    der::{oid::ObjectIdentifier, Any, Decode, DecodePem, Encode},
    Certificate,
};

/// id-envelopedData, RFC 5652 section 6.
const ID_ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

#[derive(Debug, thiserror::Error)]
pub enum SmimeError {
    #[error("certificate for {0}: {1}")]
    Certificate(String, String),
    #[error("certificate for {0} has expired or is not yet valid")]
    NotValid(String),
    #[error("S/MIME encryption failed: {0}")]
    Encrypt(String),
}

/// A recipient's certificate, checked to hold an RSA key.
pub struct Recipient {
    pub address: String,
    cert: Certificate,
    key: RsaPublicKey,
}

impl Recipient {
    /// PEM or DER. The certificate must be valid at `now` (Unix seconds).
    pub fn from_bytes(address: &str, bytes: &[u8], now: u64) -> Result<Self, SmimeError> {
        let bad = |err: String| SmimeError::Certificate(address.to_string(), err);
        let cert = if bytes.starts_with(b"-----BEGIN") {
            Certificate::from_pem(bytes).map_err(|err| bad(err.to_string()))?
        } else {
            Certificate::from_der(bytes).map_err(|err| bad(err.to_string()))?
        };
        let validity = &cert.tbs_certificate.validity;
        let (from, until) = (
            validity.not_before.to_unix_duration().as_secs(),
            validity.not_after.to_unix_duration().as_secs(),
        );
        if now < from || now > until {
            return Err(SmimeError::NotValid(address.to_string()));
        }
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|err| bad(err.to_string()))?;
        let key = RsaPublicKey::from_public_key_der(&spki)
            .map_err(|_| bad("only RSA certificates are supported".into()))?;
        Ok(Self {
            address: address.to_string(),
            cert,
            key,
        })
    }

    /// `<dir>/<address>.pem`, the address in lower case. `None` when there
    /// is no file for that address.
    pub fn find(dir: &Path, address: &str, now: u64) -> Result<Option<Self>, SmimeError> {
        let name = address.trim().to_ascii_lowercase();
        // The address becomes a file name: no separators, no hidden files.
        if name.is_empty() || name.starts_with('.') || name.contains(['/', '\\', '\0']) {
            return Ok(None);
        }
        match std::fs::read(dir.join(format!("{name}.pem"))) {
            Ok(bytes) => Self::from_bytes(address, &bytes, now).map(Some),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(SmimeError::Certificate(
                address.to_string(),
                err.to_string(),
            )),
        }
    }
}

/// The message with its content replaced by enveloped-data for `recipients`.
pub fn encrypt(raw: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, SmimeError> {
    if recipients.is_empty() {
        return Err(SmimeError::Encrypt("no recipients".into()));
    }
    let (fields, body) = split_message(raw);
    // The inner entity: the Content-* fields and the body, in canonical CRLF form.
    let mut inner = Vec::with_capacity(raw.len());
    let mut outer = Vec::new();
    for field in fields {
        let name = field_name(field);
        if name.starts_with("content-") {
            inner.extend_from_slice(&crlf(field));
        } else if name != "mime-version" {
            outer.extend_from_slice(&crlf(field));
        }
    }
    inner.extend_from_slice(b"\r\n");
    inner.extend_from_slice(&crlf(body));

    let enveloped = {
        let mut rngs = vec![rand::rngs::OsRng; recipients.len()];
        let mut builder =
            EnvelopedDataBuilder::new(None, &inner, ContentEncryptionAlgorithm::Aes256Cbc, None)
                .map_err(|err| SmimeError::Encrypt(err.to_string()))?;
        for (recipient, rng) in recipients.iter().zip(rngs.iter_mut()) {
            let rid = RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: recipient.cert.tbs_certificate.issuer.clone(),
                serial_number: recipient.cert.tbs_certificate.serial_number.clone(),
            });
            let info = KeyTransRecipientInfoBuilder::new(
                rid,
                KeyEncryptionInfo::Rsa(recipient.key.clone()),
                rng,
            )
            .map_err(|err| SmimeError::Encrypt(err.to_string()))?;
            builder
                .add_recipient_info(info)
                .map_err(|err| SmimeError::Encrypt(err.to_string()))?;
        }
        builder
            .build_with_rng(&mut rand::rngs::OsRng)
            .map_err(|err| SmimeError::Encrypt(err.to_string()))?
    };
    let der = ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::encode_from(&enveloped)
            .map_err(|err| SmimeError::Encrypt(err.to_string()))?,
    }
    .to_der()
    .map_err(|err| SmimeError::Encrypt(err.to_string()))?;
    inner.iter_mut().for_each(|b| *b = 0);

    outer.extend_from_slice(
        b"MIME-Version: 1.0\r\n\
          Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n\
          Content-Transfer-Encoding: base64\r\n\
          Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\r\n",
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(76) {
        outer.extend_from_slice(line);
        outer.extend_from_slice(b"\r\n");
    }
    Ok(outer)
}

/// Bare LF line endings become CRLF.
fn crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 16);
    let mut prev = 0u8;
    for &b in bytes {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cms::enveloped_data::{EnvelopedData, RecipientInfo};
    use rsa::{pkcs8::EncodePrivateKey, Pkcs1v15Encrypt, RsaPrivateKey};
    use x509_cert::der::asn1::OctetString;

    const NOW: u64 = 1_790_000_000;

    /// A self-signed RSA certificate generated for the test.
    fn identity(address: &str) -> (RsaPrivateKey, Vec<u8>) {
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(Default::default()).unwrap();
        let pair =
            rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, address);
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let cert = params.self_signed(&pair).unwrap();
        (key, cert.pem().into_bytes())
    }

    fn decrypt(message: &[u8], key: &RsaPrivateKey) -> Vec<u8> {
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        let (_, body) = split_message(message);
        let text: String = String::from_utf8_lossy(body).split_whitespace().collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap();
        let info = ContentInfo::from_der(&der).unwrap();
        assert_eq!(info.content_type, ID_ENVELOPED_DATA);
        let enveloped: EnvelopedData = info.content.decode_as().unwrap();
        let cek = enveloped
            .recip_infos
            .0
            .iter()
            .find_map(|ri| match ri {
                RecipientInfo::Ktri(ktri) => {
                    key.decrypt(Pkcs1v15Encrypt, ktri.enc_key.as_bytes()).ok()
                }
                _ => None,
            })
            .expect("a recipient info for this key");
        let content = &enveloped.encrypted_content;
        let iv: OctetString = content
            .content_enc_alg
            .parameters
            .as_ref()
            .unwrap()
            .decode_as()
            .unwrap();
        cbc::Decryptor::<aes::Aes256>::new_from_slices(&cek, iv.as_bytes())
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(content.encrypted_content.as_ref().unwrap().as_bytes())
            .unwrap()
    }

    const MESSAGE: &[u8] = b"From: payroll@example.com.au\r\n\
To: partner@partner.example.com.au\r\n\
Subject: Payroll\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
TFN 123 456 782\r\n";

    #[test]
    fn encrypt_smime_round_trips_for_every_recipient() {
        let (alice, alice_pem) = identity("partner@partner.example.com.au");
        let (bob, bob_pem) = identity("audit@partner.example.com.au");
        let recipients = [
            Recipient::from_bytes("partner@partner.example.com.au", &alice_pem, NOW).unwrap(),
            Recipient::from_bytes("audit@partner.example.com.au", &bob_pem, NOW).unwrap(),
        ];
        let sealed = encrypt(MESSAGE, &recipients).unwrap();
        let text = String::from_utf8_lossy(&sealed);
        assert!(text.contains("Subject: Payroll\r\n"));
        assert!(text.contains("smime-type=enveloped-data"));
        assert!(!text.contains("123 456 782"));
        assert!(!text.contains("text/plain"));
        let expected = b"Content-Type: text/plain; charset=utf-8\r\n\r\nTFN 123 456 782\r\n";
        assert_eq!(decrypt(&sealed, &alice), expected);
        assert_eq!(decrypt(&sealed, &bob), expected);
    }

    #[test]
    fn encrypt_smime_finds_certificates_by_address() {
        let dir = tempfile::tempdir().unwrap();
        let (_, pem) = identity("partner@partner.example.com.au");
        std::fs::write(dir.path().join("partner@partner.example.com.au.pem"), &pem).unwrap();
        let found = Recipient::find(dir.path(), "Partner@Partner.example.com.au", NOW).unwrap();
        assert!(found.is_some());
        assert!(
            Recipient::find(dir.path(), "other@partner.example.com.au", NOW)
                .unwrap()
                .is_none()
        );
        assert!(Recipient::find(dir.path(), "../etc/passwd", NOW)
            .unwrap()
            .is_none());
        // Outside its validity period the certificate is refused.
        assert!(matches!(
            Recipient::from_bytes("partner@partner.example.com.au", &pem, 4_000_000_000),
            Err(SmimeError::NotValid(_))
        ));
    }

    #[test]
    fn encrypt_smime_refuses_non_rsa_certificates() {
        let pair = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&pair)
            .unwrap();
        let err = Recipient::from_bytes("a@example.com.au", cert.der(), NOW)
            .err()
            .unwrap();
        assert!(err.to_string().contains("only RSA"), "{err}");
    }
}
