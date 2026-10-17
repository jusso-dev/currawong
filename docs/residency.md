# Australian data residency

`residency.mode = "au"` is the default. The gateway refuses to open a client that would carry message content to a host outside the configured rules.

Rules are host suffixes, exact names and CIDRs. `s3.ap-southeast-2.amazonaws.com` and `s3.ap-southeast-4.amazonaws.com` are the default object-storage suffixes (Sydney and Melbourne). On-premises ranges and `localhost` are allowed. A name is allowed when it equals a suffix or ends with `.{suffix}`. Lookalikes fail. The guard does not use GeoIP and it does not resolve names.

Content clients (`SandboxClient`, `LlmClient`, `ObjectStoreClient`, `WebhookClient`) call the guard before they can be constructed. `currawongd --check-config` runs the same check on `residency.content_endpoints`. A `us-east-1` bucket fails startup.

An override is an explicit URL plus a reason and an approver. The guard records it in the audit log and includes it in the residency report. Reports are canonical JSON signed with Ed25519. The signing key file is mode `0600` on Unix.

`residency.mode = "off"` disables the check. Leave it on for any deployment that handles Australian government, health or finance mail.
