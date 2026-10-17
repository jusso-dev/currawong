#!/usr/bin/env python3
"""Expect-style check of the appliance serial console (ttyS0), std-only.

Connects to a QEMU serial socket, waits for the currawong-setup wizard and,
with --complete, fills it in and waits for currawongd to start. Everything
read is appended to --log. Exits non-zero with a reason on any timeout.

  qemu-system-x86_64 ... -chardev socket,id=ser0,path=serial.sock,server=on,wait=off \\
      -serial chardev:ser0
  packaging/appliance/serial-expect.py --socket serial.sock --timeout 300 --complete

--complete also logs in as root on the serial console and checks that
currawongd and nftables are active and /healthz answers 200 inside the VM.
"""
import argparse
import re
import socket
import sys
import time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>78]")
WIZARD = "Currawong setup"
RUNNING = "Currawong is running"


class Console:
    def __init__(self, path, log, deadline):
        self.log = open(log, "ab")
        self.deadline = deadline
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(path)
                break
            except OSError:
                self.sock.close()
                if time.monotonic() > deadline:
                    fail(f"could not connect to {path}")
                time.sleep(1)
        self.sock.settimeout(1)
        self.raw = b""
        self.text = ""
        self.pos = 0

    def expect(self, needle, what, bad=None):
        """Wait for `needle` after the previous match, in ANSI-stripped output.
        Fail at once if `bad` appears first."""
        while (found := self.text.find(needle, self.pos)) < 0:
            if bad and self.text.find(bad, self.pos) >= 0:
                fail(f"{what}: saw {bad!r}. Last console text:\n{self.text[-3000:]}")
            if time.monotonic() > self.deadline:
                tail = self.text[-2000:]
                fail(f"timed out waiting for {what} ({needle!r}). Last console text:\n{tail}")
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                fail(f"console closed while waiting for {what}")
            self.log.write(chunk)
            self.log.flush()
            self.raw += chunk
            # Strip the whole buffer, so an escape split across reads is
            # still removed. Cursor moves between words become spaces.
            plain = ANSI.sub(b" ", self.raw).decode("utf-8", "replace")
            self.text = re.sub(r"[ \t]+", " ", plain)
        self.pos = found + len(needle)
        print(f"ok: {what}", flush=True)

    def send(self, data, pause=0.15):
        for ch in data:
            self.sock.sendall(ch.encode())
            time.sleep(pause)


def fail(reason):
    print(f"FAIL: {reason}", file=sys.stderr, flush=True)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--log", default="serial.log")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--complete", action="store_true",
                        help="fill in the wizard and wait for currawongd to start")
    args = parser.parse_args()
    console = Console(args.socket, args.log, time.monotonic() + args.timeout)
    console.expect(WIZARD, "the setup wizard on ttyS0")
    if not args.complete:
        return
    console.expect("[ Save ]", "the wizard form")
    time.sleep(2)
    password = "ci-only-password-1"
    console.send("\x7f" * 64)                 # clear the default hostname
    console.send("gw.example.test\t")
    console.send("example.test\t")
    console.send("127.0.0.1:2526\t")
    console.send("\t")                        # relay networks: keep 10.0.0.0/8
    console.send(" \t")                       # clamd off: no signatures in CI
    console.send("\t")                        # new self-signed certificate: on
    console.send(password + "\t")
    console.send(password + "\t")
    console.send("\r")                        # Save
    console.expect(RUNNING, "the wizard to save and start currawongd")
    console.send("\r")
    console.expect("login:", "the serial login prompt after setup")
    # Log in and check the daemon from inside the VM. The result markers are
    # computed by the shell, so the echoed command line cannot match them.
    console.send("root\r")
    console.expect("Password:", "the password prompt")
    console.send(password + "\r")
    console.expect("#", "a root shell")
    console.send(
        "for i in $(seq 1 30); do curl -fsS http://127.0.0.1:9090/healthz >/dev/null && break; sleep 1; done; "
        "if systemctl is-active --quiet currawongd nftables && curl -fsS http://127.0.0.1:9090/healthz >/dev/null; "
        "then echo HEALTHZ-$((6*7))-OK; else systemctl status currawongd nftables --no-pager; "
        "journalctl -b -u nftables --no-pager -n 50; echo HEALTHZ-$((6*7))-BAD; fi\r",
        pause=0.02,
    )
    console.expect("HEALTHZ-42-OK", "currawongd active and /healthz 200 in the VM", bad="HEALTHZ-42-BAD")


if __name__ == "__main__":
    main()
