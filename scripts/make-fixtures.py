#!/usr/bin/env python3
"""Write benign fixtures: a PE magic stub, a docm with a placeholder macro part, and a small zip.

Does not write EICAR or any real malware.
"""
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "testdata" / "fixtures"


def pe_stub() -> bytes:
    blob = bytearray(0x80)
    blob[0:2] = b"MZ"
    blob[0x3C] = 0x40
    blob[0x40:0x44] = b"PE\x00\x00"
    return bytes(blob)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "invoice.pdf").write_bytes(pe_stub())
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"benign-placeholder")
    (ROOT / "note.docm").write_bytes(buffer.getvalue())
    small = io.BytesIO()
    with zipfile.ZipFile(small, "w") as archive:
        archive.writestr("readme.txt", b"hello")
    (ROOT / "small.zip").write_bytes(small.getvalue())
    print(f"wrote fixtures in {ROOT}")


if __name__ == "__main__":
    main()
