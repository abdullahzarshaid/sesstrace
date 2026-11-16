#!/usr/bin/env python3
"""Phase 3b adapter for Vikunja link shares (T5.grant_withdrawn). It speaks the contract of phases 1 and 2 and nothing more;
it keeps no session table, caches nothing and decides nothing by itself. Python standard library only.
Usage: python3 vikunja_share_adapter.py <port> <application request log> ; reads passwords from /secrets, the application is app:3456.
sid carries the link-share token that the application issues for the share of the user's project (POST /api/v1/shares/:share/auth)
unchanged. /profile is GET /api/v1/projects with that token: it lists the project the share grants, and the project title
(set by the set-up) names the share. The application's GET /api/v1/user is not used because it reads the share row at both
releases (see SPEC_CELLS_3B.json, identity_request)."""
import http.client, json, re, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), open(sys.argv[2], "a")
APP = ("app", 3456)
TITLE = {"alice": "p3b project alice", "bob": "p3b project bob"}
DENIAL = {(500, "Could not determine the current user."), (401, "missing, malformed, expired or otherwise invalid token provided")}


def secret(name):
    return open("/secrets/" + name, encoding="utf-8").read().strip()


def call(method, path, body=None, bearer=None):
    c = http.client.HTTPConnection(*APP, timeout=20)
    h = {}
    data = json.dumps(body).encode() if body is not None else None
    if data is not None: h["Content-Type"] = "application/json"
    if bearer: h["Authorization"] = "Bearer " + bearer
    c.request(method, path, body=data, headers=h)
    r = c.getresponse(); raw = r.read(); c.close()
    LOG.write("%s %s %s %d\n" % (time.strftime("%H:%M:%S"), method, re.sub(r"/shares/[^/]+/auth", "/shares/<hash>/auth", path.split("?")[0]), r.status)); LOG.flush()
    try:
        j = json.loads(raw or b"{}")
    except ValueError:
        j = {}
    return r.status, j


def owner(user):
    """The user's own token, the id of the user's project and its link share (id, hash), read from the application."""
    s, j = call("POST", "/api/v1/login", {"username": user, "password": secret(user + "_password"), "long_token": False})
    tok = j.get("token") if s == 200 and isinstance(j, dict) else None
    s, projects = call("GET", "/api/v1/projects", bearer=tok) if tok else (None, [])
    pid = next((p["id"] for p in projects if isinstance(p, dict) and p.get("title") == TITLE[user]), None) if s == 200 and isinstance(projects, list) else None
    s, shares = call("GET", "/api/v1/projects/%s/shares" % pid, bearer=tok) if pid else (None, [])
    share = shares[0] if s == 200 and isinstance(shares, list) and shares else {}
    return tok, pid, share.get("id"), share.get("hash")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send(self, code, obj, sid=None):
        body = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        if sid: self.send_header("Set-Cookie", "sid=%s; Path=/; HttpOnly" % sid)
        self.end_headers(); self.wfile.write(body)

    def sid(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid": return v

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path); q = dict(urllib.parse.parse_qsl(u.query)); user = q.get("user")
        try:
            if u.path == "/ready":
                s, _ = call("GET", "/api/v1/info")
                return self.send(200, {"ok": True}) if s == 200 else self.send(503, {"error": "unrecognized"})
            if u.path == "/login" and user in TITLE:
                _, _, _, hsh = owner(user)
                s, j = call("POST", "/api/v1/shares/%s/auth" % hsh, {"password": ""}) if hsh else (None, {})
                t = j.get("token") if s == 200 else None
                return self.send(200, {"logged_in": True}, sid=t) if t else self.send(502, {"error": "unrecognized"})
            if u.path == "/profile":
                s, j = call("GET", "/api/v1/projects", bearer=self.sid())
                if s == 200 and isinstance(j, list) and len(j) == 1:
                    name = {v: k for k, v in TITLE.items()}.get(j[0].get("title"))
                    if name: return self.send(200, {"sub": name, "rp": "RP1"})
                if isinstance(j, dict) and (s, j.get("message")) in DENIAL: return self.send(401, {"error": "no_session"})
                return self.send(502, {"error": "unrecognized"})
            if u.path == "/delete_share" and user in TITLE:
                tok, pid, shid, _ = owner(user)
                s, _ = call("DELETE", "/api/v1/projects/%s/shares/%s" % (pid, shid), bearer=tok) if shid else (None, None)
                return self.send(200, {"terminated": True}) if s == 200 else self.send(502, {"error": "unrecognized"})
            self.send(404, {"error": "not_found"})
        except (OSError, http.client.HTTPException):
            self.send(502, {"error": "unrecognized"})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
