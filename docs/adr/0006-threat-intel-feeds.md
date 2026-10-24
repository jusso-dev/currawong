# ADR 0006: Threat-intelligence feeds

Status: Accepted

## Context
Commercial gateways check attachments and links against cloud reputation services (FortiGuard, Proofpoint, Mimecast). Each lookup sends the hash or URL, and often the message, to the vendor. Currawong keeps message content on the box (ARCHITECTURE goal 3, ADR 0005), so it cannot do that. Public and government feeds publish the same kind of indicators in bulk: abuse.ch (URLhaus, ThreatFox, MalwareBazaar), OpenPhish, PhishTank, and STIX 2.1 over TAXII 2.1 from the ACSC Cyber Threat Intelligence Sharing platform (CTIS) and MISP communities.

## Decision
- Feeds are downloaded into a local SQLite store (`crates/intel`). Every lookup, at scan time and at click time, is a local read. A download sends the feed key, if any, and our user agent; it carries nothing about any message, so feed URLs are not residency endpoints and are not checked by the residency guard.
- Downloads are HTTPS only, redirects only to HTTPS, size capped before and after decompression, with a timeout and conditional GET. Each feed's indicators are replaced in one transaction. A failed, unparseable or empty download keeps the previous data. A feed that stops syncing is reported stale after a configured number of refresh periods, and its indicators stop matching `expire_after_days` after its last good sync, so a dead feed does not block reused domains for ever.
- Indicators are SHA-256 hashes, URLs, domains and addresses, normalised so a feed entry and a link compare as strings. A link matches by URL, by its host or any parent domain down to the registrable domain, or by its address. Hits are report data and policy flags (`intel.hash`, `intel.url`, `intel.domain`, `intel.ip`, `intel.<feed>`); the default packs quarantine them. The engine adds no verdict of its own.
- Exception, opt-in: Spamhaus DQS. With a DQS key, link domains are looked up in DBL and part hashes in HBL over DNS. Each query sends the registrable domain or the Base32 SHA-256 digest, with the key, to Spamhaus through the system resolver. No message content, address or header is sent. It is off by default and documented in the example config as leaving the box.
- Keys come from an environment variable or a file named in config, never from the config file itself, and never appear in logs or stored errors.
- No cloud multi-scanner and no per-message reputation API (ADR 0005).

## Feed terms (as published in October 2026; operators must check current terms)
- abuse.ch URLhaus, ThreatFox and MalwareBazaar: an Auth-Key from auth.abuse.ch is required and goes in the export URL path (the keyless download paths answer 410). The terms of use effective 4 November 2025 allow free non-commercial use within fair-use query and export volumes; commercial use may need a Spamhaus subscription. These three datasets are no longer described as CC0 (Feodo Tracker, SSL Blacklist and YARAify still are). The data may not be used to train AI models without Spamhaus's consent.
- OpenPhish community feed (`feed.txt`): free for non-commercial use under OpenPhish's terms, refreshed about every 12 hours. Commercial feeds are separate.
- PhishTank: data dumps need an application key; downloads are under Cisco's terms of use, hourly, with a rate limit on downloads.
- Spamhaus DQS: free use is limited by Spamhaus's DQS terms (non-commercial, volume limits); queries through public resolvers are refused.
- ACSC CTIS and MISP: access and redistribution follow the sharing agreement and the TLP marking of each collection.

## Consequences
Detection depends on what operators subscribe to and on feed freshness; the local store lags the source by up to one refresh period. Feeds with many entries (PhishTank, ThreatFox full) need the download cap raised. Mail is never held waiting for a feed: a stale or empty store only means fewer hits. The DQS exception reveals to Spamhaus which domains and attachment hashes reach the gateway, and is therefore opt-in.

## Alternatives considered
Online lookups per message (Google Safe Browsing, VirusTotal, URLhaus API): reveal every link and hash to a third party, add latency and a hard dependency. Rejected. RPZ zones in a local resolver: covers domains only, not hashes or full URLs.
