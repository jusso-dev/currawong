# ADR 0007: On-box Rspamd spam and phishing engine

Status: Accepted

## Context

Bayes and local rules remain useful without external services. Optional Rspamd adds mature spam/phishing signals without linking its code or sending mail to a cloud multi-scanner (ADR 0005).

## Decision

- Rspamd runs as a separate on-box HTTP service (Apache-2.0). An absent `scanner.rspamd.url` disables it. Currawong POSTs raw MIME to `/checkv2`, with envelope metadata and repeated `Rcpt` headers, alongside ClamAV.
- Every HTTP request is residency-checked, resolved and pinned. Environment proxies and automatic redirects are disabled. Responses are capped at 1 MiB, messages at `max_size`, and the whole request including DNS at `timeout_secs`.
- The report carries score, threshold, normalised action, symbols and messages. Policy sees raw `rspamd`, `rspamd.ratio` when the threshold is positive, action flags and up to 256 positive symbol flags. Phishing symbols are retained first. Zero thresholds do not produce a ratio.
- Reject holds in `spam`; add-header/rewrite-subject mark `X-Spam: Yes`; PHISHING/PHISHED_* hold in `phishing`. Greylist/soft-reject defer. Existing Bayes/rules scoring is unchanged.
- Unreachable required service defers; optional service adds a note. Invalid protocol replies, redirects and scan size limits fail closed. Required readiness probes `/ping`.
- A separate optional `controller_url` enables `/learnham` on spam releases, even with Bayes disabled. The client also supports `/learnspam`; there is no existing administrator mark-spam hook to wire. Passwords come from files and travel only in the `Password` header. Learning failure is logged without holding release delivery.

## Consequences

Rspamd configuration, signature/rule freshness, Redis persistence and any external lookups it performs remain operator responsibilities. Currawong's residency guard covers its own HTTP traffic, not Rspamd's network access. Learning retries rely on Rspamd's duplicate-learning protection. No real Rspamd deployment was exercised. See [integration guide](../integrations/rspamd.md) and [validation](../VALIDATION.md).
