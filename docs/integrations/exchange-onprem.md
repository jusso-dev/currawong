# Exchange Server on-premises

Currawong can sit in front of an on-premises Exchange organisation running
Exchange Server 2016, Exchange Server 2019 or Exchange Server Subscription
Edition (SE). Currawong becomes the MX. It relays inbound mail to Exchange
through a dedicated Receive connector, and Exchange sends outbound mail
through a Send connector that uses Currawong as its smart host.

Exchange 2013 and earlier are out of support and are not covered.

| Version | Supported | Notes |
| --- | --- | --- |
| Exchange Server 2016 | Yes | Cumulative Update 23 or later recommended. |
| Exchange Server 2019 | Yes | |
| Exchange Server SE | Yes | SE uses the same cmdlets and connector model as 2019. The scripts are identical apart from the version named in their comments. |

```
Internet --25--> Currawong --25, TLS required--> Exchange Mailbox servers ("Currawong Inbound" Receive connector)
Exchange ("Currawong Outbound" Send connector) --25 or 587, TLS required--> Currawong --> Internet
```

## 1. Configure the domain in Currawong

Add the domain to `domains.accept` and give it an `exchange_onprem` route.
Inbound mail goes to the listed Mailbox servers in order; if a server refuses
the connection or fails the session (including a failed TLS handshake), the
next one is tried. A host whose name does not resolve is skipped with a
warning in the log. TLS is always required on this route, and the Exchange
certificate must be valid for `tls_cert_name`. The domain is matched without
regard to case or a trailing dot, the same way for the hosts and for the TLS
rule. Host entries and `tls_cert_name` are checked when the configuration
loads, and the route's PEM files are parsed at startup and by
`--check-config` (an unreadable or empty CA file, a bad certificate or key,
or a key that does not match its certificate is an error), so a mistake
stops startup rather than deferring mail.

```toml
[domains]
accept = ["agency.example"]

[[domains.routes]]
domain = "agency.example"
mailbox_platform = "exchange_onprem"
exchange_version = "2019"            # "2016", "2019" or "se"
mailbox_hosts = ["exch01.agency.example", "exch02.agency.example"]
tls_cert_name = "mail.agency.example"
# ca_file = "/etc/currawong/agency-ca.pem"   # internal CA, see Certificates
# client_cert = "/etc/currawong/exchange-client.pem"  # opt in: domain secure
# client_key = "/etc/currawong/exchange-client.key"

# Outbound: Currawong treats mail from the Exchange servers' source addresses
# as outbound relay for this tenant (the trusted relay CIDRs).
[[relay.tenants]]
id = "agency"
domains = ["agency.example"]
trusted_cidrs = ["192.0.2.25/32", "192.0.2.26/32"]
```

Mail relayed from those addresses to outside domains is outbound mail: it is
DLP scanned, DKIM signed with the tenant's active key, and delivered by
Currawong. Mail from any other address that is not for an accepted domain is
refused as relaying.

If the tenant prefers SMTP AUTH (the Send connector authenticates on 587),
create a relay credential for it instead of listing the addresses, and tick
"SMTP AUTH" in the wizard.

`mailbox_platform = "m365"` and `"google_workspace"` are accepted as labels
only; those routes still deliver to their `next_hop` like a plain smart host.

## 2. Run the onboarding wizard

> Screenshot placeholder: wizard step "Exchange on-premises", values form.

The wizard page and its verify button are pending the admin UI (#39). Until
then `currawong_admin::onboarding::exchange::render_scripts` renders the same
scripts, from `ExchangeOnboarding::from_config`.

The wizard renders PowerShell from the tenant's real values: Currawong's host
name and addresses, the domains, the Exchange Mailbox server names and
`limits.max_message_bytes`. It refuses values that are not plain host names,
server names or addresses, so a setting cannot inject PowerShell. It also
refuses duplicate servers or addresses, loopback, multicast or unspecified
gateway addresses, a size above Exchange's 2 GB limit, and lock-down ranges
that cover every address or have host bits set. Each script is run in the
Exchange Management Shell, and each is safe to run again: connectors are only
created if missing, and the first run's backups are kept.

| Script | Run | What it does |
| --- | --- | --- |
| `receive.ps1` | Once; it covers every Mailbox server | Creates "Currawong Inbound" on each server with `-RequireTLS $true`, `-RemoteIPRanges` limited to Currawong's addresses and a message size limit equal to Currawong's. Domain secure: `-Usage Partner`, `-PermissionGroups Partners`, `-AuthMechanism Tls`, `-DomainSecureEnabled $true`. Otherwise: `-Usage Custom -PermissionGroups AnonymousUsers`. |
| `send.ps1` | Once | Creates "Currawong Outbound" with `-SmartHosts` set to Currawong, `-RequireTLS $true`, `-TlsAuthLevel DomainValidation` and `-TlsDomain` set to Currawong's host name, on port 25 (or 587 with `BasicAuthRequireTLS` and `Get-Credential` for SMTP AUTH). |
| `transport.ps1` | Once | On its first run, saves the current `MaxReceiveSize` and `MaxSendSize`, and whether Currawong was already on the domain secure lists, to `currawong-transport-backup.xml` in the admin's profile. Sets both sizes to Currawong's limit and, when domain secure, adds Currawong to `TLSReceiveDomainSecureList` and `TLSSendDomainSecureList` if missing. |
| `rollback.ps1` | Only to back out | Removes both connectors, restores the saved sizes, takes Currawong off the domain secure lists only if the transport script added it, and restores Default Frontend's saved ranges if it was locked down (warning if that backup is missing, for example when run from another account). It deletes the backups it used. |

The Receive connector is domain secure (Partner, mutual TLS) only when the
route sets `client_cert` and `client_key`. This is opt in: the gateway's
`tls.cert` is never used as the client certificate, because a public-CA server
certificate often lacks the client authentication usage Exchange requires.
Currawong presents the route's certificate whenever Exchange asks for one.
Without it the wizard renders the anonymous connector, since a Partner
connector would refuse every delivery:

- **Anonymous Receive connector.** `-Usage Custom -PermissionGroups
  AnonymousUsers` with `-RequireTLS $true`. The remote IP restriction is then
  the key control: keep `-RemoteIPRanges` to Currawong's addresses only.

Option:

- **Lock down Default Frontend** (off unless ticked). Restricts each server's
  `Default Frontend <server>` connector to the internal ranges you enter, so
  internet mail cannot bypass Currawong. Warning: anything outside those
  ranges, including an old MX or another gateway, is refused. List every
  internal sender (applications, devices, other Exchange servers) first. The
  first run saves each connector's current ranges to
  `currawong-frontend-<server>.xml`; the rollback script puts them back.

> Screenshot placeholder: rendered scripts with copy buttons.

## 3. Publish DNS

Currawong does not change customer DNS. The wizard shows the records:

```
agency.example. IN MX 10 gw.currawong.example.
agency.example. IN TXT "v=spf1 ip4:203.0.113.10 ip4:203.0.113.11 -all"
```

If the domain already has an SPF record, add Currawong's `ip4:`/`ip6:`
mechanisms to it before its `all` term rather than publishing a second one.

## 4. Verify

> Screenshot placeholder: wizard verify step.

The verify step will run the Exchange connector health checks (#52) and mark
the domain active only when they pass. The step waits for the admin UI (#39)
and the checks are not built yet, so for now check by hand:

```powershell
Get-ReceiveConnector "EXCH01\Currawong Inbound" | fl RemoteIPRanges,RequireTLS,PermissionGroups,MaxMessageSize
Get-SendConnector "Currawong Outbound" | fl SmartHosts,RequireTLS,TlsAuthLevel,TlsDomain,Port
Get-TransportConfig | fl MaxReceiveSize,MaxSendSize,TLSReceiveDomainSecureList,TLSSendDomainSecureList
```

Then send a test message in each direction and check the Exchange protocol
log (`-ProtocolLoggingLevel Verbose` is set on the Receive connector) shows
TLS.

## Certificates

Both directions require TLS and check names, so both sides need certificates
the other trusts.

- **Exchange's certificate, checked by Currawong.** Currawong delivers only
  over STARTTLS and checks that the certificate presented by each Mailbox
  server is valid for `tls_cert_name` and chains to a trusted root. Public CA
  certificates work with the built-in WebPKI roots. For an internal enterprise
  CA, put that CA's certificate (PEM) in `ca_file`; it is trusted in addition
  to the WebPKI roots, for this route only. A self-signed Exchange
  certificate is not supported: issue one from your CA. Certificate pinning
  is not supported. TLS verification cannot be turned off. If a Mailbox server
  does not offer STARTTLS, or its certificate does not verify, the message is
  deferred with the reason and retried, never sent in plaintext. The CA file
  and client certificate are re-read only when one of the files changes, so a
  renewed certificate is picked up without a restart.
- **Currawong's certificate, checked by Exchange.** The Send connector uses
  `-TlsAuthLevel DomainValidation -TlsDomain <Currawong host name>`, so
  Exchange must trust the certificate configured in `tls.cert`. For a domain
  secure Receive connector, Exchange also checks the client certificate
  Currawong presents (the route's `client_cert`): it must name Currawong's
  host name, allow client authentication (the TLS Web Client Authentication
  extended key usage, or none), and chain to a CA the Exchange servers trust.
  Use a public CA, or add your CA to the Exchange servers' Trusted Root
  Certification Authorities.

## Rollback

1. Point the MX records back at the previous host and wait for the old TTL.
2. Run `rollback.ps1` in the Exchange Management Shell.
3. Remove the `exchange_onprem` route and the tenant's trusted CIDRs from
   Currawong.

## Not verified

These scripts were generated and checked against golden files, but have not
been run against a lab Exchange server. See `docs/VALIDATION.md`.
