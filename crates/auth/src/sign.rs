//! Outbound DKIM signing and ARC sealing.
use crate::keys::StoredKey;
use base64::{engine::general_purpose::STANDARD, Engine};
use mail_auth::{
    arc::ArcSealer,
    common::{
        crypto::{Ed25519Key, RsaKey, Sha256},
        headers::HeaderWriter,
        parse::TxtRecordParser,
        verify::DomainKey,
    },
    dkim::DkimSigner,
    ArcOutput, AuthenticatedMessage, AuthenticationResults,
};

pub fn sign_message(raw: &[u8], key: &StoredKey) -> Result<Vec<u8>, String> {
    let signature = match key.algorithm.as_str() {
        "ed25519" => {
            let signer =
                Ed25519Key::from_pkcs8_der(&key.private_key).map_err(|err| err.to_string())?;
            DkimSigner::from_key(signer)
                .domain(key.domain.clone())
                .selector(key.selector.clone())
                .headers([
                    "From",
                    "From",
                    "To",
                    "Subject",
                    "Date",
                    "Message-ID",
                    "MIME-Version",
                    "Content-Type",
                ])
                .sign(raw)
                .map_err(|err| err.to_string())?
        }
        _ => {
            #[allow(deprecated)]
            let signer = RsaKey::<Sha256>::from_pkcs8_der(&key.private_key)
                .map_err(|err| err.to_string())?;
            DkimSigner::from_key(signer)
                .domain(key.domain.clone())
                .selector(key.selector.clone())
                .headers([
                    "From",
                    "From",
                    "To",
                    "Subject",
                    "Date",
                    "Message-ID",
                    "MIME-Version",
                    "Content-Type",
                ])
                .sign(raw)
                .map_err(|err| err.to_string())?
        }
    };
    let mut header = Vec::new();
    signature.write(&mut header, true);
    if !header.ends_with(b"\r\n") {
        header.extend_from_slice(b"\r\n");
    }
    header.extend_from_slice(raw);
    Ok(header)
}

pub fn seal_arc(raw: &[u8], key: &StoredKey, authserv_id: &str) -> Result<Vec<u8>, String> {
    let message = AuthenticatedMessage::parse(raw).ok_or("ARC input did not parse")?;
    let results = AuthenticationResults::new(authserv_id);
    let arc_output = ArcOutput::default();
    let set = match key.algorithm.as_str() {
        "ed25519" => {
            let signer =
                Ed25519Key::from_pkcs8_der(&key.private_key).map_err(|err| err.to_string())?;
            ArcSealer::from_key(signer)
                .domain(key.domain.clone())
                .selector(key.selector.clone())
                .headers(["From", "To", "Subject", "Date"])
                .seal(&message, &results, &arc_output)
                .map_err(|err| err.to_string())?
        }
        _ => {
            #[allow(deprecated)]
            let signer = RsaKey::<Sha256>::from_pkcs8_der(&key.private_key)
                .map_err(|err| err.to_string())?;
            ArcSealer::from_key(signer)
                .domain(key.domain.clone())
                .selector(key.selector.clone())
                .headers(["From", "To", "Subject", "Date"])
                .seal(&message, &results, &arc_output)
                .map_err(|err| err.to_string())?
        }
    };
    let header = set.to_header();
    let mut out = header.into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

pub fn rsa_key(bits: usize) -> Result<StoredKey, String> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;
    let mut rng = rand::rngs::OsRng;
    let private = RsaPrivateKey::new(&mut rng, bits).map_err(|err| err.to_string())?;
    let der = private.to_pkcs8_der().map_err(|err| err.to_string())?;
    #[allow(deprecated)]
    let signer = RsaKey::<Sha256>::from_pkcs8_der(der.as_bytes()).map_err(|err| err.to_string())?;
    let public = STANDARD.encode(signer.public_key());
    let txt = format!("v=DKIM1; k=rsa; p={public}");
    DomainKey::parse(txt.as_bytes()).map_err(|err| format!("generated rsa record: {err}"))?;
    Ok(StoredKey {
        id: "generated-rsa".into(),
        tenant_id: "local".into(),
        domain: "example.test".into(),
        selector: "currawong".into(),
        algorithm: "rsa-sha256".into(),
        private_key: der.as_bytes().to_vec(),
        public_txt: txt,
        created_at: crate::keys::now_secs(),
        retired_at: None,
        active: true,
    })
}

pub fn ed25519_key() -> Result<StoredKey, String> {
    let der = Ed25519Key::generate_pkcs8().map_err(|err| err.to_string())?;
    let signer = Ed25519Key::from_pkcs8_der(&der).map_err(|err| err.to_string())?;
    let public = STANDARD.encode(signer.public_key());
    let txt = format!("v=DKIM1; k=ed25519; p={public}");
    DomainKey::parse(txt.as_bytes()).map_err(|err| format!("generated ed25519 record: {err}"))?;
    Ok(StoredKey {
        id: "generated-ed25519".into(),
        tenant_id: "local".into(),
        domain: "example.test".into(),
        selector: "ed".into(),
        algorithm: "ed25519".into(),
        private_key: der,
        public_txt: txt,
        created_at: crate::keys::now_secs(),
        retired_at: None,
        active: true,
    })
}
