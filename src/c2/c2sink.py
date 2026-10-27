#!/usr/bin/env python3
"""C2 sink — the exfiltration endpoint the advisory points at.

Runs on the compromised relay (:4443). Records every payload it receives with a
timestamp and source address. The verifier uses the newest timestamp here to tell
whether the analyst actually cut the exfil flow.
"""
import json
import os
import socketserver
import time

LOOT = "/var/lib/c2/loot.jsonl"
os.makedirs(os.path.dirname(LOOT), exist_ok=True)


class Sink(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:
            line = raw.strip()
            if not line:
                continue
            with open(LOOT, "a") as fh:
                fh.write(json.dumps({
                    "ts": time.time(),
                    "src": self.client_address[0],
                    "bytes": len(line),
                    "sample": line[:200].decode("utf-8", "replace"),
                }) + "\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", 4443), Sink).serve_forever()
