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

- The header wins when it is valid; otherwise the subject marking is used.
- `pspf.invalid`: a marking is present but breaks the syntax above, or there
  is more than one `X-Protective-Marking` header.
- `pspf.mismatch`: header and subject both carry a marking and disagree on the
  classification or the `ACCESS` markers.
- `pspf.missing`: no marking at all.
- Policy conditions: `{ marking = "PROTECTED" }` (exact), `{ marking_at_least =
  "PROTECTED" }` (that level or higher) and `{ not = { ... } }`.

## Government pack

`config/policies/government.toml` is the default pack plus:

| Policy | Effect |
| --- | --- |
| `pspf-secret` | Outbound SECRET and TOP-SECRET are rejected. |
| `pspf-protected-external` | Outbound PROTECTED to anything but `*.gov.au` is rejected. Add partner domains as extra `not` conditions. |
| `pspf-invalid`, `pspf-mismatch` | Outbound mail with a broken or inconsistent marking is quarantined in `pspf`. |
| `pspf-default-marking` | Disabled by default. When enabled, adds `SEC=OFFICIAL` to unmarked outbound mail. |

Enforcing TLS for PROTECTED mail needs the `require_tls` action from #35.
