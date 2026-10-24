#!/bin/sh
# Copy benign seeds into the cargo-fuzz corpus directories.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
corpus="$root/fuzz/corpus"
for target in smtp_command smtp_data smtp_sasl mime_parse archive_extract \
  office_detect doc_scan pspf_parse url_rewrite dlp_scan auth_strip clamd_address \
  parser_ipc spool_envelope; do
  mkdir -p "$corpus/$target"
done
if [ -d "$root/testdata/corpus" ]; then
  cp "$root/testdata/corpus/"*.eml "$corpus/mime_parse/"
  cp "$root/testdata/corpus/"*.eml "$corpus/smtp_data/"
  cp "$root/testdata/corpus/"*.eml "$corpus/auth_strip/"
  cp "$root/testdata/corpus/dlp.eml" "$corpus/pspf_parse/"
  cp "$root/testdata/corpus/dlp.eml" "$corpus/dlp_scan/"
  cp "$root/testdata/corpus/phish.eml" "$corpus/url_rewrite/"
fi
if [ -d "$root/testdata/auth" ]; then
  cp "$root/testdata/auth/"*.eml "$corpus/auth_strip/"
fi
if [ -d "$root/testdata/fixtures" ]; then
  cp "$root/testdata/fixtures/"* "$corpus/archive_extract/" 2>/dev/null || true
  cp "$root/testdata/fixtures/"* "$corpus/office_detect/" 2>/dev/null || true
fi
printf 'EHLO example.test\r\n' > "$corpus/smtp_command/ehlo"
printf 'MAIL FROM:<a@example.test> SIZE=1000\r\n' > "$corpus/smtp_command/mail"
printf 'Subject: hi\r\n\r\n..hidden\r\nhello\r\n.\r\n' > "$corpus/smtp_data/dot"
printf 'LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\n' > "$corpus/smtp_sasl/login"
printf 'PLAIN AHVzZXIAcGFzcw==\r\n' > "$corpus/smtp_sasl/plain"
printf 'tcp:127.0.0.1:3310' > "$corpus/clamd_address/tcp"
printf 'unix:/run/clamav/clamd.ctl' > "$corpus/clamd_address/unix"
printf '{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","rcpt_to":[]}' > "$corpus/spool_envelope/partial"
printf '\000\000\000\076{"id":"a","raw_path":"/x","limits":{"max_depth":1,"max_uncompressed_bytes":1,"max_files":1,"max_ratio":1}}' \
  > "$corpus/parser_ipc/request"
printf '\000%%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (x) >> >>\nendobj\n' > "$corpus/doc_scan/pdf"
printf '\002<svg xmlns="http://www.w3.org/2000/svg" onload="x"/>' > "$corpus/doc_scan/svg"
printf '\003[InternetShortcut]\r\nURL=file://server/share/a\r\n' > "$corpus/doc_scan/url"
echo "seeded $corpus"
