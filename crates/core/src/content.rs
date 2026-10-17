//! Constructors for clients that would carry message content off the gateway.
//! Each one calls the residency guard before it can be used.
use crate::residency::{ResidencyError, ResidencyGuard};
use url::Url;

#[derive(Debug, Clone)]
pub struct ContentEndpoint {
    url: Url,
}

impl ContentEndpoint {
    pub fn open(guard: &ResidencyGuard, url: &str) -> Result<Self, ResidencyError> {
        let url = Url::parse(url).map_err(|err| ResidencyError::Invalid(err.to_string()))?;
        guard.check(&url)?;
        Ok(Self { url })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }
}

macro_rules! content_client {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            endpoint: ContentEndpoint,
        }

        impl $name {
            pub fn new(guard: &ResidencyGuard, url: &str) -> Result<Self, ResidencyError> {
                Ok(Self {
                    endpoint: ContentEndpoint::open(guard, url)?,
                })
            }

            pub fn endpoint(&self) -> &Url {
                self.endpoint.url()
            }

            pub fn kind(&self) -> &'static str {
                $kind
            }
        }
    };
}

content_client!(SandboxClient, "sandbox");
content_client!(LlmClient, "llm");
content_client!(ObjectStoreClient, "object-store");
content_client!(WebhookClient, "webhook");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResidencyConfig;
    use crate::residency::ResidencyGuard;

    #[test]
    fn content_clients_refuse_a_foreign_bucket() {
        let guard = ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap();
        let err =
            ObjectStoreClient::new(&guard, "https://mail.s3.us-east-1.amazonaws.com/quarantine")
                .unwrap_err();
        assert!(matches!(err, ResidencyError::Denied(_)));
        WebhookClient::new(&guard, "https://10.4.5.6/siem").unwrap();
        LlmClient::new(&guard, "https://llm.example.com/v1").unwrap_err();
    }
}
