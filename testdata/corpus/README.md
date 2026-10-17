# Sample corpus

These messages are benign text. They are not exploits.

The gateway decides malware, active content, fail-closed scans and DMARC `p=reject` today. It does not score spam, phishing, BEC or DLP yet. The expected verdicts in `expected.toml` say `deliver` for those samples on purpose, with a TODO naming the issue that will change each one. Quarantining them now would be a false claim.

`macro.eml` carries the benign `testdata/fixtures/note.docm` macro fixture and is quarantined by the `active-content` policy.

The EICAR message is not stored here. `currawong_testkit::eicar_message()` builds it at run time from XOR bytes. With a scanner enabled (the corpus test uses the testkit's fake clamd), that message is quarantined.

`123456782` in the DLP sample is a published TFN checksum example, not a real tax file number.
