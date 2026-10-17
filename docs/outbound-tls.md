# Outbound TLS: DANE, MTA-STS and TLS-RPT

Currawong picks the TLS rule for each MX host in this order.

1. **DANE (RFC 7672).** DANE is used when three things hold: the MX answer was DNSSEC-validated, the host's A and AAAA records (and any CNAME on the way) were validated, and the TLSA RRset was validated. If the host name is a CNAME, `_25._tcp.<target>` is tried first, then `_25._tcp.<mx>`. STARTTLS is required, and the certificate must match a DANE-TA(2) or DANE-EE(3) record. Any of the following defers that host:
   - the certificate does not match;
   - STARTTLS is missing;
   - the TLSA lookup is bogus, indeterminate or fails;
   - the signed TLSA RRset holds only unusable records, such as PKIX-TA(0) or PKIX-EE(1).

   Delivery never falls back to clear text or to an unchecked certificate.
2. **MTA-STS (RFC 8461).** Currawong checks the `_mta-sts.<domain>` TXT record and fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`. The fetch uses WebPKI validation and no redirects, and the policy is cached in the `mta_sts_policy` table for `max_age`.
   - A cached policy is refreshed early, once half its `max_age` has passed. A new TXT `id` also triggers a refetch.
   - If a refetch fails, the cached policy stays in force, and the failure is remembered for five minutes before the next try.
   - Discovery for one domain runs once at a time.
   - In `enforce` mode, an MX host the policy does not list is skipped, and a host whose certificate does not validate for its name defers. In `testing` mode, failures are only reported.
3. **Opportunistic.** STARTTLS is used when the server offers it, and the certificate is verified against the WebPKI roots. If verification fails, the message goes on a fresh connection without TLS. It is never sent over TLS that has not been verified, and there is no option to allow that.
   - Every clear-text delivery is logged at warning level and counted in `currawong_delivery_tls_fallback_total{reason}`. The reasons are `starttls_not_offered`, `starttls_refused`, `tls_failed` and `sts_testing`.
   - The message's `Received` header gains the comment `(relayed onward without TLS)`.
   - Set `delivery.require_tls = true` to defer instead. That setting also covers `domains.routes` next hops, which DANE and MTA-STS do not apply to.

WebPKI roots are the Mozilla set shipped in `webpki-roots`.

## Limits

- **MX hosts and addresses.** At most 5 MX hosts and 10 addresses are tried per domain. Hosts of equal preference are tried in random order.
- **Time and connections.** One `deliver` call is bounded at 30 minutes. At most `delivery.max_per_destination` sessions are open to one recipient domain.
- **When the next host is tried.** A 4xx at MAIL or RCPT moves those recipients on to the next MX host. A recipient fails permanently only when every host that was tried failed permanently.
- **Recipient domains.** A domain that is not a plain host name is refused before any DNS query.
- **Outbound HTTP.** Policy fetches and TLS-RPT uploads use only `https` URLs on port 443 that name a plain host, and those names must resolve to public addresses. The one exception is `delivery.allow_private_mx`. The core residency guard is not yet wired in. Its single call site is `residency_check` in `crates/smtp/src/delivery/outbound_tls.rs`.

## DNSSEC

With `delivery.dane = true`, delivery lookups go through a resolver that validates DNSSEC itself from the root trust anchor. The system resolver must pass DNSSEC records (RRSIG, DNSKEY, DS) through. A forwarder that strips them makes signed zones look bogus, and mail to those domains will defer. Check this before you enable DANE, or set `delivery.dane = false`.

## Bounces

A permanent failure is bounced only to a sender we can stand behind:

- mail submitted by our own users (outbound, or carrying a tenant);
- mail whose sender passed SPF or DMARC.

A failure is never bounced to the null sender, to a malformed address, or for mail marked `Auto-Submitted`. Anything else is logged and dropped. DSNs are limited to 10 an hour per sender address and 100 an hour per sender domain. They carry `Auto-Submitted: auto-generated`. Expired messages are reported with Status 5.4.7.

## TLS-RPT (RFC 8460)

Every session made under a DANE or MTA-STS policy is counted by UTC day in `tlsrpt_session`. Policy texts are stored once in `tlsrpt_policy`. Policy discovery failures are counted too. Deliveries of TLS-RPT reports themselves are not counted.

After the day ends, each policy domain that publishes `_smtp._tls` with a `rua` gets one report:

- A `mailto:` address gets a gzip JSON attachment, queued from the null sender.
- An `https:` address gets an `application/tlsrpt+gzip` POST. Uploads go one at a time, each with a 60-second limit.

Reports are capped as follows:

- 5 `rua` addresses;
- 20 policies, each with up to 50 failure details (session totals stay exact);
- 1 MiB of JSON.

A domain whose report fails is retried on a later pass without holding up the others. The report pass runs on its own task every ten minutes.

Set `organization-name` with `delivery.tls_rpt.organisation`. Set `contact-info` with `delivery.tls_rpt.contact`. It defaults to `postmaster@<gateway.hostname>`.

## Publishing MTA-STS for your own domains

Currawong does not host policy sites. To protect mail sent to your domains:

1. Serve `https://mta-sts.<your-domain>/.well-known/mta-sts.txt` as `text/plain` with a publicly trusted certificate for `mta-sts.<your-domain>`. Any static web host or CDN will do. Start with this:

   ```
   version: STSv1
   mode: testing
   mx: mx1.<your-domain>
   max_age: 86400
   ```

   List every MX host that receives your mail, and make sure each one presents a valid certificate for its own name.
2. Publish `_mta-sts.<your-domain>. TXT "v=STSv1; id=<yyyymmddnn>"`. Change the `id` whenever the policy changes.
3. Publish `_smtp._tls.<your-domain>. TXT "v=TLSRPTv1; rua=mailto:tlsrpt@<your-domain>"` to receive reports from other senders.
4. When the reports are clean, switch to `mode: enforce` and raise `max_age`, for example to 604800. Update the `id` when you do.
