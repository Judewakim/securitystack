#!/usr/bin/env python3
"""Run the web app locally with a fake API (no AWS needed).

    python3 scripts/dev_server.py        # then open http://localhost:8000

The fake API walks through the real flow (create session -> start -> RUNNING ->
DONE) and returns web/demo.json as the result, so you can work on the UI offline.
Any role ARN of the right shape is accepted.
"""

import http.server
import json
import pathlib
import re
import secrets
import time

WEB = pathlib.Path(__file__).resolve().parents[1] / "web"
SCANS = {}


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(WEB), **kw)

    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/scans":
            sid = secrets.token_urlsafe(24)
            SCANS[sid] = {"status": "AWAITING_ROLE"}
            region = body.get("homeRegion", "us-east-1")
            return self._json(201, {
                "scanId": sid, "externalId": "ss-dev", "homeRegion": region,
                "roleLaunchUrl": f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/quickcreate?stackName=SecurityStackScanRole",
            })
        m = re.fullmatch(r"/api/scans/([\w-]{32})/start", self.path)
        if m and m.group(1) in SCANS:
            if "bad" in body.get("roleArn", ""):
                return self._json(400, {"error": "That doesn't look like the RoleArn output of the SecurityStackScanRole stack."})
            SCANS[m.group(1)] = {"status": "QUEUED", "at": time.time()}
            return self._json(202, {"status": "QUEUED"})
        return self._json(404, {"error": "Not found."})

    def do_GET(self):
        m = re.fullmatch(r"/api/scans/([\w-]{32})", self.path)
        if m:
            scan = SCANS.get(m.group(1))
            if not scan:
                return self._json(404, {"error": "Scan not found or expired."})
            if scan["status"] == "QUEUED" and time.time() - scan["at"] > 4:
                return self._json(200, {"status": "DONE", "result": json.loads((WEB / "demo.json").read_text())})
            return self._json(200, {"status": "RUNNING" if scan["status"] == "QUEUED" else scan["status"]})
        return super().do_GET()


if __name__ == "__main__":
    print("Serving http://localhost:8000 (fake API)")
    http.server.ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
