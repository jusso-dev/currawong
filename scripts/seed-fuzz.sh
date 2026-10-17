#!/bin/sh
# Copy benign seeds into the cargo-fuzz corpus directories.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
corpus="$root/fuzz/corpus"
mkdir -p \
  "$corpus/smtp_command" \
  "$corpus/smtp_data" \
  "$corpus/mime_parse" \
  "$corpus/archive_extract" \
  "$corpus/pspf_parse" \
  "$corpus/url_rewrite" \
  "$corpus/dlp_scan"
if [ -d "$root/testdata/corpus" ]; then
  cp "$root/testdata/corpus/"*.eml "$corpus/mime_parse/"
  cp "$root/testdata/corpus/dlp.eml" "$corpus/pspf_parse/"
  cp "$root/testdata/corpus/dlp.eml" "$corpus/dlp_scan/"
  cp "$root/testdata/corpus/phish.eml" "$corpus/url_rewrite/"
fi
if [ -d "$root/testdata/fixtures" ]; then
  cp "$root/testdata/fixtures/"* "$corpus/archive_extract/" 2>/dev/null || true
fi
printf 'EHLO example.test\r\n' > "$corpus/smtp_command/ehlo"
printf 'Subject: hi\r\n\r\nhello\r\n.\r\n' > "$corpus/smtp_data/dot"
echo "seeded $corpus"
