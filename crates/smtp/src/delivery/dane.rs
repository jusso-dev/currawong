//! DANE for SMTP (RFC 7672): which TLSA records count, and a rustls verifier
//! that authenticates the server against them. It fails closed: no matching
//! record means no session, never a fallback to unauthenticated TLS.
use crate::dns::Tlsa;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Arc;

const DANE_TA: u8 = 2;
const DANE_EE: u8 = 3;

/// RFC 7672 section 3.1: only DANE-TA(2) and DANE-EE(3) are usable for SMTP.
/// PKIX-TA(0) and PKIX-EE(1) and unknown parameters are dropped.
pub fn usable(records: &[Tlsa]) -> Vec<Tlsa> {
    records
        .iter()
        .filter(|record| matches!(record.usage, DANE_TA | DANE_EE))
        .filter(|record| matches!(record.selector, 0 | 1))
        .filter(|record| match record.matching {
            0 => !record.data.is_empty(),
            1 => record.data.len() == 32,
            2 => record.data.len() == 64,
            _ => false,
        })
        .cloned()
        .collect()
}

/// Does `record` match `cert` under its selector and matching type?
pub fn matches(record: &Tlsa, cert: &CertificateDer<'_>) -> bool {
    let selected = match record.selector {
        0 => cert.to_vec(),
        1 => match webpki::EndEntityCert::try_from(cert) {
            Ok(parsed) => parsed.subject_public_key_info().to_vec(),
            Err(_) => return false,
        },
        _ => return false,
    };
    let digest = match record.matching {
        0 => selected,
        1 => Sha256::digest(&selected).to_vec(),
        2 => Sha512::digest(&selected).to_vec(),
        _ => return false,
    };
    digest == record.data
}

#[derive(Debug)]
pub struct DaneVerifier {
    records: Vec<Tlsa>,
    /// Reference identifiers for DANE-TA: the TLSA base domain (the MX host)
    /// and the next-hop domain (RFC 7672 section 3.2.2).
    names: Vec<ServerName<'static>>,
    provider: Arc<CryptoProvider>,
}

impl DaneVerifier {
    pub fn new(
        records: Vec<Tlsa>,
        names: Vec<ServerName<'static>>,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            records,
            names,
            provider,
        }
    }

    /// DANE-TA: the matched certificate is the only trust anchor, and the
    /// usual chain, name and validity checks apply beneath it.
    fn chains_to(
        &self,
        anchor: &CertificateDer<'_>,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> bool {
        let mut roots = RootCertStore::empty();
        if roots.add(anchor.clone().into_owned()).is_err() {
            return false;
        }
        let Ok(verifier) = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&self.provider),
        )
        .build() else {
            return false;
        };
        self.names.iter().any(|name| {
            verifier
                .verify_server_cert(end_entity, intermediates, name, &[], now)
                .is_ok()
        })
    }
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        for record in &self.records {
            match record.usage {
                // DANE-EE: the key or certificate itself; names and dates are
                // not checked (RFC 7672 section 3.1.1).
                DANE_EE if matches(record, end_entity) => {
                    return Ok(ServerCertVerified::assertion())
                }
                // The server must send the trust anchor in its chain
                // (RFC 7672 section 3.1.2).
                DANE_TA => {
                    for anchor in intermediates {
                        if matches(record, anchor)
                            && self.chains_to(anchor, end_entity, intermediates, now)
                        {
                            return Ok(ServerCertVerified::assertion());
                        }
                    }
                }
                _ => {}
            }
        }
        Err(Error::General(
            "DANE: no TLSA record matches the server certificate chain".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlsa(usage: u8, selector: u8, matching: u8, data: Vec<u8>) -> Tlsa {
        Tlsa {
            usage,
            selector,
            matching,
            data,
        }
    }

    #[test]
    fn only_dane_usages_with_sane_data_are_usable() {
        let records = vec![
            tlsa(3, 1, 1, vec![0; 32]),
            tlsa(2, 0, 2, vec![0; 64]),
            tlsa(1, 1, 1, vec![0; 32]),
            tlsa(0, 0, 1, vec![0; 32]),
            tlsa(3, 1, 1, vec![0; 31]),
            tlsa(3, 2, 1, vec![0; 32]),
            tlsa(3, 1, 9, vec![0; 32]),
        ];
        let kept = usable(&records);
        assert_eq!(kept, records[..2].to_vec());
    }

    #[test]
    fn selectors_and_matching_types() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["mx.example.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().clone();
        let spki = key.public_key_der();
        assert!(matches(&tlsa(3, 0, 0, der.to_vec()), &der));
        assert!(matches(&tlsa(3, 0, 1, Sha256::digest(&der).to_vec()), &der));
        assert!(matches(
            &tlsa(3, 1, 1, Sha256::digest(&spki).to_vec()),
            &der
        ));
        assert!(matches(
            &tlsa(3, 1, 2, Sha512::digest(&spki).to_vec()),
            &der
        ));
        assert!(!matches(&tlsa(3, 1, 1, vec![0; 32]), &der));
    }
}
