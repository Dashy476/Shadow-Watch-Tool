#!/usr/bin/env python3
"""SENTINEL-01 cUAS console.

Port 8080 is the operator console: friendly, hostile, and unknown tracks,
one focused track path, and a diagnostics export for a logged-in user.
Port 9000 accepts detections from EDGE-02 only. The SENSOR that feeds
EDGE-02 is out of scope and is not contacted. Track lines are appended
for log-forward.py, which sends them on to OPS-03.
"""

from __future__ import annotations

import html
import json
import os
import secrets
import threading
import time
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import StreamRequestHandler, ThreadingTCPServer
from urllib.parse import parse_qs

CONSOLE_PORT = int(os.environ.get("CONSOLE_PORT", "8080"))
INGEST_PORT = int(os.environ.get("INGEST_PORT", "9000"))
EDGE_IP = os.environ.get("EDGE_IP", "10.80.40.12")
PASSWD_PATH = os.environ.get("CONSOLE_PASSWD", "/etc/sw/console.passwd")
TRACK_LOG = os.environ.get("TRACK_LOG", "/var/log/sentinel/tracks.log")
EXPORT_PATH = os.environ.get(
    "EXPORT_PATH", "/var/lib/sentinel/diagnostics/export/latest.json"
)
TRACK_DIR = os.environ.get("TRACK_DIR", "/var/lib/sentinel/tracks")
MAX_TRACKS = 24

CLASSES = ("friendly", "hostile", "unknown")


def load_users(path: str) -> dict[str, str]:
    users = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            user, password = line.split(":", 1)
            users[user] = password
    if not users:
        raise SystemExit(f"no accounts in {path}")
    return users


class Store:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.tracks: dict[str, dict] = {}
        self.order: list[str] = []
        self.sessions: dict[str, str] = {}
        self.users = load_users(PASSWD_PATH)
        os.makedirs(TRACK_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(EXPORT_PATH), exist_ok=True)
        os.makedirs(os.path.dirname(TRACK_LOG), exist_ok=True)
        # Kept open so a live snapshot sees the diagnostics export and track log.
        self.export_fh = open(EXPORT_PATH, "w", encoding="utf-8")
        self.log_fh = open(TRACK_LOG, "a", encoding="utf-8")
        self._rewrite_export()

    def check(self, user: str, password: str) -> bool:
        expected = self.users.get(user)
        if expected is None:
            return False
        return compare_digest(expected, password)

    def login(self, user: str) -> str:
        token = secrets.token_hex(16)
        with self.lock:
            self.sessions[token] = user
        return token

    def user_for(self, token: str) -> str:
        with self.lock:
            return self.sessions.get(token, "")

    def logout(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)

    def add(self, body: dict, peer: str) -> dict | None:
        track_id = str(body.get("id") or "").strip()
        kind = str(body.get("class") or "").strip().lower()
        if not track_id or kind not in CLASSES:
            return None
        points = body.get("points") if isinstance(body.get("points"), list) else []
        clean_points = []
        for point in points[:32]:
            if not isinstance(point, dict):
                continue
            clean_points.append(
                {
                    "t": int(point.get("t") or time.time()),
                    "lat": float(point.get("lat") or 0),
                    "lon": float(point.get("lon") or 0),
                    "alt": float(point.get("alt") or 0),
                }
            )
        track = {
            "id": track_id,
            "class": kind,
            "callsign": str(body.get("callsign") or track_id)[:32],
            "source": "EDGE-02",
            "peer": peer,
            "received": time.time(),
            "points": clean_points,
        }
        with self.lock:
            self.tracks[track_id] = track
            if track_id in self.order:
                self.order.remove(track_id)
            self.order.append(track_id)
            while len(self.order) > MAX_TRACKS:
                dropped = self.order.pop(0)
                self.tracks.pop(dropped, None)
            self._write_track(track)
            self._rewrite_export()
        return track

    def snapshot(self) -> dict:
        with self.lock:
            tracks = [self.tracks[key] for key in self.order if key in self.tracks]
        latest = tracks[-1]["received"] if tracks else None
        return {
            "host": "SENTINEL-01",
            "export": "diagnostics",
            "console_port": CONSOLE_PORT,
            "ingest_port": INGEST_PORT,
            "track_count": len(tracks),
            "latest_unix": latest,
            "tracks": tracks,
        }

    def _write_track(self, track: dict) -> None:
        path = os.path.join(TRACK_DIR, f"{track['id']}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(track, handle)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(track["received"]))
        self.log_fh.write(
            f"{stamp} track id={track['id']} class={track['class']} "
            f"callsign={track['callsign']} source=EDGE-02 points={len(track['points'])}\n"
        )
        self.log_fh.flush()

    def _rewrite_export(self) -> None:
        tracks = [self.tracks[key] for key in self.order if key in self.tracks]
        latest = tracks[-1]["received"] if tracks else None
        payload = {
            "host": "SENTINEL-01",
            "export": "diagnostics",
            "console_port": CONSOLE_PORT,
            "ingest_port": INGEST_PORT,
            "track_count": len(tracks),
            "latest_unix": latest,
            "tracks": tracks,
        }
        text = json.dumps(payload)
        self.export_fh.seek(0)
        self.export_fh.truncate()
        self.export_fh.write(text)
        self.export_fh.flush()


STATE: Store


def cookie_token(header: str) -> str:
    for part in (header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "session":
            return value
    return ""


def page(title: str, body: str, status: int = 200) -> tuple[int, bytes]:
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; color: #1a1a1a; }}
table {{ border-collapse: collapse; }}
td, th {{ border-bottom: 1px solid #ccc; padding: 0.35rem 0.8rem; text-align: left; }}
a {{ color: #0b3d91; }}
.hostile {{ color: #8d1d1d; }}
.friendly {{ color: #146c2e; }}
.unknown {{ color: #6b4e00; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
{body}
</body>
</html>
"""
    return status, document.encode("utf-8")


class ConsoleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[console] {self.address_string()} {fmt % args}", flush=True)

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status: int, payload: bytes, extra: dict | None = None) -> None:
        self._send(status, payload, "text/html; charset=utf-8", extra)

    def _authed(self) -> str:
        return STATE.user_for(cookie_token(self.headers.get("Cookie", "")))

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 100_000:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items() if values}

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            body = json.dumps({"ok": True, "role": "SENTINEL-01"}).encode("utf-8")
            self._send(200, body, "application/json")
            return
        if path == "/logout":
            STATE.logout(cookie_token(self.headers.get("Cookie", "")))
            self._html(302, b"", {"Location": "/", "Set-Cookie": "session=; HttpOnly; Path=/; Max-Age=0"})
            return
        user = self._authed()
        if path == "/diagnostics/export":
            if not user:
                self._html(401, page("Sign in required", "<p>The diagnostics export is for a signed-in operator.</p>")[1])
                return
            body = json.dumps(STATE.snapshot()).encode("utf-8")
            self._send(200, body, "application/json")
            return
        if path.startswith("/track/"):
            if not user:
                self._html(*page("cUAS console", self._login_form()))
                return
            self._html(*self._focus(path[len("/track/"):]))
            return
        if path != "/":
            self._html(404, page("Not found", "<p>That page is not on this console.</p>")[1])
            return
        if not user:
            self._html(*page("cUAS console", self._login_form()))
            return
        self._html(*page("cUAS console", self._table(user)))

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/login":
            self._html(404, page("Not found", "<p>That page is not on this console.</p>")[1])
            return
        form = self._form()
        user = form.get("username", "")
        password = form.get("password", "")
        if not STATE.check(user, password):
            message = self._login_form("Those credentials were not accepted.")
            self._html(401, page("cUAS console", message)[1])
            return
        token = STATE.login(user)
        self._html(
            302,
            b"",
            {"Location": "/", "Set-Cookie": f"session={token}; HttpOnly; Path=/"},
        )

    def _login_form(self, error: str = "") -> str:
        note = f"<p>{html.escape(error)}</p>" if error else ""
        return f"""
{note}
<p>SENTINEL-01 cUAS console. Sign in to see tracks and the diagnostics export.</p>
<form method="post" action="/login">
<label>User <input name="username" autocomplete="username"></label><br><br>
<label>Password <input name="password" type="password" autocomplete="current-password"></label><br><br>
<button type="submit">Sign in</button>
</form>
"""

    def _table(self, user: str) -> str:
        snap = STATE.snapshot()
        rows = []
        for track in reversed(snap["tracks"]):
            kind = html.escape(track["class"])
            rows.append(
                "<tr>"
                f"<td><a href=\"/track/{html.escape(track['id'])}\">{html.escape(track['id'])}</a></td>"
                f"<td class=\"{kind}\">{kind}</td>"
                f"<td>{html.escape(track['callsign'])}</td>"
                f"<td>{len(track['points'])}</td>"
                "</tr>"
            )
        body_rows = "\n".join(rows) or "<tr><td colspan=\"4\">No detections yet.</td></tr>"
        return f"""
<p>Signed in as {html.escape(user)}. Detections arrive from EDGE-02. Logs are forwarded to OPS-03.</p>
<p><a href="/diagnostics/export">Diagnostics export</a> · <a href="/logout">Sign out</a></p>
<table>
<thead><tr><th>Track</th><th>Class</th><th>Callsign</th><th>Points</th></tr></thead>
<tbody>
{body_rows}
</tbody>
</table>
"""

    def _focus(self, track_id: str) -> tuple[int, bytes]:
        snap = STATE.snapshot()
        track = next((item for item in snap["tracks"] if item["id"] == track_id), None)
        if track is None:
            return page("Track not found", f"<p>No current track {html.escape(track_id)}.</p><p><a href=\"/\">Back</a></p>", 404)
        points = []
        for point in track["points"]:
            points.append(
                "<tr>"
                f"<td>{point['t']}</td>"
                f"<td>{point['lat']:.5f}</td>"
                f"<td>{point['lon']:.5f}</td>"
                f"<td>{point['alt']:.0f}</td>"
                "</tr>"
            )
        kind = html.escape(track["class"])
        body = f"""
<p><a href="/">All tracks</a></p>
<p>Callsign {html.escape(track['callsign'])} · class <span class="{kind}">{kind}</span> · source EDGE-02</p>
<h2>Path</h2>
<table>
<thead><tr><th>Time</th><th>Lat</th><th>Lon</th><th>Alt</th></tr></thead>
<tbody>
{''.join(points) or '<tr><td colspan="4">No path points.</td></tr>'}
</tbody>
</table>
"""
        return page(f"Track {track['id']}", body)


class IngestHandler(StreamRequestHandler):
    def handle(self) -> None:
        peer = self.client_address[0]
        if peer != EDGE_IP:
            print(f"[ingest] rejected {peer}", flush=True)
            return
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                body = json.loads(line)
            except json.JSONDecodeError:
                print("[ingest] ignored a non-JSON line", flush=True)
                continue
            if not isinstance(body, dict):
                continue
            track = STATE.add(body, peer)
            if track is None:
                print("[ingest] ignored a detection missing id or class", flush=True)
            else:
                print(f"[ingest] {track['id']} {track['class']}", flush=True)


def main() -> None:
    global STATE
    STATE = Store()
    ThreadingTCPServer.allow_reuse_address = True
    ThreadingHTTPServer.allow_reuse_address = True
    ingest = ThreadingTCPServer(("0.0.0.0", INGEST_PORT), IngestHandler)
    ingest.daemon_threads = True
    threading.Thread(target=ingest.serve_forever, name="ingest", daemon=True).start()
    console = ThreadingHTTPServer(("0.0.0.0", CONSOLE_PORT), ConsoleHandler)
    print(
        f"cuas-console listening on {CONSOLE_PORT}, ingest on {INGEST_PORT} from {EDGE_IP}",
        flush=True,
    )
    console.serve_forever()


if __name__ == "__main__":
    main()
