-- What the policy decision required of delivery, applied again on release
-- (#55). `tls` is a TlsRequirement (`none`, `opportunistic`, `required`,
-- `dane`); `encrypt` is NULL for none, or `auto`, `smime` or `portal`.
ALTER TABLE quarantine ADD COLUMN tls TEXT NOT NULL DEFAULT 'none';
ALTER TABLE quarantine ADD COLUMN encrypt TEXT;

-- Earlier builds kept neither. A message they held because it could not be
-- encrypted has a reason starting `encrypt` (all such holds but an S/MIME
-- library error): release encrypts it, or holds it again, rather than send
-- it in clear. A policy whose id starts `encrypt` matches too, which errs
-- towards encrypting. Other old rows keep the gateway's own TLS rules, as
-- before; their policy's TLS requirement was not recorded.
UPDATE quarantine SET encrypt = 'smime' WHERE reason GLOB 'encrypt_smime:*';
UPDATE quarantine SET encrypt = 'auto' WHERE encrypt IS NULL AND reason GLOB 'encrypt*';
