# PSPF protective markings

Currawong reads the `X-Protective-Marking` header and the `[SEC=...]` subject
marking defined by the Australian Government Email Protective Marking Standard
(EPMS), checks them, and exposes the result to policy.

## Version followed

The parser follows the EPMS header syntax as published for versions 2018.6
and 2024.1 (the `VER=` values in current Microsoft Purview guidance for
Australian Government tenants):

```
X-Protective-Marking: VER=<version>, NS=<namespace>, SEC=<classification>,
  CAVEAT=<type>:<value>, EXPIRES=<date|event>, DOWNTO=<classification>,
  ACCESS=<information management marker>, NOTE=<comment>, ORIGIN=<author email>
```

`VER`, `NS` and `SEC` are required and the fields must appear in that order.
`CAVEAT` and `ACCESS` may repeat. `EXPIRES` and `DOWNTO` go together, and
`DOWNTO` must be lower than `SEC`. Classifications are `UNOFFICIAL`,
`OFFICIAL`, `OFFICIAL:Sensitive`, `PROTECTED`, `SECRET` and `TOP-SECRET`
(case-insensitive; `OFFICIAL Sensitive` and `OFFICIAL-Sensitive` are
accepted). Information management markers are `Legal-Privilege`,
`Legislative-Secrecy` and `Personal-Privacy`.

The subject form is `[SEC=<classification>(, CAVEAT=...)*(, ACCESS=...)*]`;
the last one in the subject is used.

protectivesecurity.gov.au lists an EPMS 2026 edition. Its text could not be
retrieved while this was written, so differences between 2024.1 and 2026 are
not reflected yet (see `docs/VALIDATION.md`).

## What the gateway does

- The effective classification is the highest level found in the header and
  every `[SEC=...]` subject marking (including any second Subject header and
  the `SEC=` level a broken marking claims), so a lower marking elsewhere can
  never lower enforcement.
- A header section larger than 256 KiB is not inspected and is flagged
  `pspf.invalid`, so padding cannot hide a marking.
- `pspf.invalid`: a marking is present but breaks the syntax above, or there
  is more than one `X-Protective-Marking` header.
- `pspf.mismatch`: header and subject both carry a marking and disagree on the
  classification or the `ACCESS` markers.
- `pspf.missing`: no marking at all.
- `pspf.caveat`, `pspf.caveat.<caveat>` (lower case, for example
  `pspf.caveat.sh:cabinet`) and `pspf.access.<marker>` (for example
  `pspf.access.legal-privilege`) for policies on caveats and markers.
- Policy conditions: `{ marking = "PROTECTED" }` (exact), `{ marking_at_least =
  "PROTECTED" }` (that level or higher) and `{ not = { ... } }`.

## Government pack

`config/policies/government.toml` is the default pack plus:

| Policy | Effect |
| --- | --- |
| `pspf-secret` | Outbound SECRET and TOP-SECRET are rejected. |
| `pspf-protected-external` | Outbound PROTECTED to anything but `*.gov.au` is rejected. Add partner domains as extra `not` conditions. |
| `pspf-invalid`, `pspf-mismatch` | Outbound mail with a broken or inconsistent marking is quarantined in `pspf`. |
| `pspf-required` | Outbound mail with no marking is quarantined in `pspf`. |
| `pspf-default-marking` | Disabled by default. The alternative to `pspf-required`: adds `SEC=OFFICIAL` to unmarked outbound mail. |

Enforcing TLS for PROTECTED mail needs the `require_tls` action from #35.

## Strictness

Values outside the classifications above, including legacy markings such as
`CONFIDENTIAL`, `RESTRICTED` and `HIGHLY PROTECTED`, are flagged invalid
rather than mapped. The government pack quarantines invalid markings, so this
fails safe; agencies still sending legacy markings will see them held.
