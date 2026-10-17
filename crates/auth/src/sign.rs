//! Outbound DKIM signing and ARC sealing.
use crate::keys::{now_secs, KeyStore, StoredKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use mail_auth::{
    arc::ArcSealer,
    common::{
        crypto::{Ed25519Key, RsaKey, Sha256, SigningKey},
        headers::HeaderWriter,
        parse::TxtRecordParser,
        verify::DomainKey,
    },
    dkim::DkimSigner,
    ArcOutput, AuthenticatedMessage, AuthenticationResults,
};
use zeroize::Zeroizing;

/// Identity and content headers are listed twice (oversigned) so a copy
/// added in transit, including one that was absent at signing, breaks the
/// signature.
const SIGNED_HEADERS: [&str; 14] = [
    "From",
    "From",
    "To",
    "To",
    "Cc",
    "Cc",
    "Reply-To",
    "Reply-To",
    "Subject",
    "Subject",
    "Date",
    "Date",
    "Message-ID",
    "Message-ID",
];
const CONTENT_HEADERS: [&str; 2] = ["MIME-Version", "Content-Type"];
const SEALED_HEADERS: [&str; 7] = [
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
];

/// One DKIM-Signature header per key (RSA and Ed25519 side by side), each
/// ending in CRLF, to prepend to `raw`.
pub fn sign(raw: &[u8], keys: &[StoredKey]) -> Result<String, String> {
    let mut out = String::new();
    for key in keys {
        let header = match key.algorithm.as_str() {
            "ed25519" => dkim_header(raw, key, ed25519(key)?)?,
            _ => dkim_header(raw, key, rsa(key)?)?,
        };
        out.push_str(&header);
        if !out.ends_with("\r\n") {
            out.push_str("\r\n");
        }
    }
    Ok(out)
}

/// `raw` with DKIM-Signature headers prepended.
pub fn sign_message(raw: &[u8], key: &StoredKey) -> Result<Vec<u8>, String> {
    let mut out = sign(raw, std::slice::from_ref(key))?.into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

/// DKIM-Signature headers for an outbound message, signed with every active
/// key `tenant_id` holds for the RFC 5322 From domain. Empty when the tenant
/// has no key for that domain.
pub fn sign_outbound(store: &KeyStore, raw: &[u8], tenant_id: &str) -> Result<String, String> {
    let message = AuthenticatedMessage::parse(raw).ok_or("outbound message did not parse")?;
    let Some(domain) = message
        .from
        .first()
        .and_then(|from| from.rsplit_once('@'))
        .map(|(_, domain)| domain.to_ascii_lowercase())
    else {
        return Ok(String::new());
    };
    let keys = store.signing_keys(tenant_id, &domain, now_secs())?;
    sign(raw, &keys)
}

fn dkim_header<T: SigningKey<Hasher = Sha256>>(
    raw: &[u8],
    key: &StoredKey,
    signer: T,
) -> Result<String, String> {
    let signature = DkimSigner::from_key(signer)
        .domain(key.domain.clone())
        .selector(key.selector.clone())
        .headers(SIGNED_HEADERS.iter().chain(CONTENT_HEADERS.iter()).copied())
        .sign(raw)
        .map_err(|err| err.to_string())?;
    Ok(signature.to_header())
}

/// ARC set (`i=` one above the existing chain, `cv=` from its validation)
/// sealing `results` onto `message`.
pub(crate) fn seal_arc_set(
    message: &AuthenticatedMessage<'_>,
    results: &AuthenticationResults<'_>,
    arc: &ArcOutput<'_>,
    key: &StoredKey,
) -> Result<String, String> {
    let set = match key.algorithm.as_str() {
        "ed25519" => ArcSealer::from_key(ed25519(key)?)
            .domain(key.domain.clone())
            .selector(key.selector.clone())
            .headers(SEALED_HEADERS)
            .seal(message, results, arc)
            .map_err(|err| err.to_string())?
            .to_header(),
        _ => ArcSealer::from_key(rsa(key)?)
            .domain(key.domain.clone())
            .selector(key.selector.clone())
            .headers(SEALED_HEADERS)
            .seal(message, results, arc)
            .map_err(|err| err.to_string())?
            .to_header(),
    };
    Ok(set)
}

fn ed25519(key: &StoredKey) -> Result<Ed25519Key, String> {
    Ed25519Key::from_pkcs8_der(&key.private_key).map_err(|err| err.to_string())
}

fn rsa(key: &StoredKey) -> Result<RsaKey<Sha256>, String> {
    #[allow(deprecated)]
    RsaKey::<Sha256>::from_pkcs8_der(&key.private_key).map_err(|err| err.to_string())
}

/// RSA-2048 PKCS#8 DER and its DKIM TXT record.
pub(crate) fn rsa_material() -> Result<(Zeroizing<Vec<u8>>, String), String> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;
    let mut rng = rand::rngs::OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).map_err(|err| err.to_string())?;
    let der = private.to_pkcs8_der().map_err(|err| err.to_string())?;
    #[allow(deprecated)]
    let signer = RsaKey::<Sha256>::from_pkcs8_der(der.as_bytes()).map_err(|err| err.to_string())?;
    let txt = format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(signer.public_key()));
    DomainKey::parse(txt.as_bytes()).map_err(|err| format!("generated rsa record: {err}"))?;
    Ok((Zeroizing::new(der.as_bytes().to_vec()), txt))
}

/// Ed25519 PKCS#8 DER and its DKIM TXT record.
pub(crate) fn ed25519_material() -> Result<(Zeroizing<Vec<u8>>, String), String> {
    let der = Zeroizing::new(Ed25519Key::generate_pkcs8().map_err(|err| err.to_string())?);
    let signer = Ed25519Key::from_pkcs8_der(&der).map_err(|err| err.to_string())?;
    let txt = format!(
        "v=DKIM1; k=ed25519; p={}",
        STANDARD.encode(signer.public_key())
    );
    DomainKey::parse(txt.as_bytes()).map_err(|err| format!("generated ed25519 record: {err}"))?;
    Ok((der, txt))
}
