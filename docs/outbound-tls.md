# Outbound TLS: DANE, MTA-STS and TLS-RPT

Currawong picks the TLS rule for each MX host in this order.

1. **DANE (RFC 7672).** Used when the MX answer and the host's address records are DNSSEC-validated and `_25._tcp.<mx>` has usable TLSA records (DANE-TA(2) or DANE-EE(3)). STARTTLS is required and the certificate must match a record. A mismatch, a missing STARTTLS, or a TLSA lookup that is bogus or fails defers that host. Delivery never falls back to clear text or to an unchecked certificate. PKIX-TA(0) and PKIX-EE(1) records are ignored, as RFC 7672 recommends. If every TLSA record is unusable, DANE does not apply and the next rule is used.
2. **MTA-STS (RFC 8461).** The `_mta-sts.<domain>` TXT record and `https://mta-sts.<domain>/.well-known/mta-sts.txt` are checked. The policy is fetched with WebPKI validation and no redirects, then cached in the `mta_sts_policy` table for `max_age`. A cached policy is used until it expires, and a new TXT `id` triggers a refetch. If a refetch fails, the cached policy stays in force. In `enforce` mode, an MX host the policy does not list is skipped, and a host whose certificate does not validate for its name defers. In `testing` mode, failures are only reported.
3. **Opportunistic.** STARTTLS is used when the server offers it, and the certificate is verified against the WebPKI roots. If verification fails, the message goes on a fresh connection without TLS. It is never sent over TLS that has not been verified. Set `delivery.require_tls = true` to defer instead. That setting also covers `domains.routes` next hops, which DANE and MTA-STS do not apply to.

WebPKI roots are the Mozilla set shipped in `webpki-roots`.

## DNSSEC

With `delivery.dane = true`, delivery lookups go through a resolver that validates DNSSEC itself from the root trust anchor. The system resolver must pass DNSSEC records (RRSIG, DNSKEY, DS) through. A forwarder that strips them makes signed zones look bogus, and mail to those domains will defer. Check that before you enable DANE, or set `delivery.dane = false`.

## TLS-RPT (RFC 8460)

Every session made under a DANE or MTA-STS policy is counted by UTC day in `tlsrpt_result`. Policy discovery failures are counted too. After the day ends, each policy domain that publishes `_smtp._tls` with a `rua` gets one report. A `mailto:` address gets a gzip JSON attachment, queued from the null sender. An `https:` address gets an `application/tlsrpt+gzip` POST. Set `organization-name` with `delivery.tls_rpt.organisation`. Set `contact-info` with `delivery.tls_rpt.contact`; it defaults to `postmaster@<gateway.hostname>`.

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
