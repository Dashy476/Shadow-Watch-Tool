#!/usr/bin/env python3
"""OPS-03 log vault.

Retains the log-forwarding flow from SENTINEL-01. Lines are appended to
/var/log/sentinel/forwarded.log and the file is kept open.
"""

from __future__ import annotations

import os
import time
from socketserver import StreamRequestHandler, ThreadingTCPServer

SENTINEL_IP = os.environ.get("SENTINEL_IP", "10.80.40.11")
LOG_PORT = int(os.environ.get("LOG_PORT", "1514"))
FORWARD_LOG = os.environ.get("FORWARD_LOG", "/var/log/sentinel/forwarded.log")


class Vault(StreamRequestHandler):
    def handle(self) -> None:
        peer = self.client_address[0]
        if peer != SENTINEL_IP:
            print(f"[syslog-vault] rejected {peer}", flush=True)
            return
        print(f"[syslog-vault] retaining logs from {peer}", flush=True)
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.server.log_fh.write(f"{stamp} {peer} {line}\n")
            self.server.log_fh.flush()


def main() -> None:
    os.makedirs(os.path.dirname(FORWARD_LOG), exist_ok=True)
    ThreadingTCPServer.allow_reuse_address = True
    server = ThreadingTCPServer(("0.0.0.0", LOG_PORT), Vault)
    server.log_fh = open(FORWARD_LOG, "a", encoding="utf-8")
    print(f"[syslog-vault] listening on {LOG_PORT}, retaining {FORWARD_LOG}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
