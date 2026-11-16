#!/usr/bin/env python3
"""Part D adapter for FUXA (T6). It speaks the contract of phases 1 and 2 and nothing more; it keeps no session table,
caches nothing and decides nothing by itself. Python standard library only.
Usage: python3 fuxa_adapter.py <port> <application request log> ; reads passwords from /secrets, the application is app:1881.
sid carries the application's own HttpOnly refresh cookie fuxa_refresh unchanged; /profile is the application's
POST /api/refresh, which answers with the username of that cookie."""
import http.client, json, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), open(sys.argv[2], "a")
APP, COOKIE = ("app", 1881), "fuxa_refresh"
DENIAL = {"Invalid refresh token", "Refresh token missing"}
USERS = ("alice", "bob")


def secret(name):
    return open("/secrets/" + name, encoding="utf-8").read().strip()


def call(method, path, body=None, cookie=None, token=None):
    c = http.client.HTTPConnection(*APP, timeout=20)
    h = {}
    data = json.dumps(body).encode() if body is not None else None
    if data is not None: h["Content-Type"] = "application/json"
    if cookie: h["Cookie"] = "%s=%s" % (COOKIE, cookie)
    if token: h["x-access-token"] = token
    c.request(method, path, body=data, headers=h)
    r = c.getresponse(); raw = r.read(); c.close()
    LOG.write("%s %s %s %d\n" % (time.strftime("%H:%M:%S"), method, path.split("?")[0], r.status)); LOG.flush()
    try:
        j = json.loads(raw or b"{}")
    except ValueError:
        j = {}
    return r.status, r.getheaders(), j if isinstance(j, dict) else {}


def set_cookie(headers, name):
    for k, v in headers:
        if k.lower() == "set-cookie" and v.startswith(name + "="):
            return v.split(";")[0].split("=", 1)[1]


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
                s, _, _ = call("GET", "/")
                return self.send(200, {"ok": True}) if s == 200 else self.send(503, {"error": "unrecognized"})
            if u.path == "/login" and user in USERS:
                s, h, _ = call("POST", "/api/signin", {"username": user, "password": secret(user + "_password")})
                v = set_cookie(h, COOKIE)
                return self.send(200, {"logged_in": True}, sid=v) if s == 200 and v else self.send(502, {"error": "unrecognized"})
            if u.path == "/profile":
                s, _, j = call("POST", "/api/refresh", cookie=self.sid())
                name = (j.get("data") or {}).get("username") if s == 200 else None
                if name in USERS: return self.send(200, {"sub": name, "rp": "RP1"})
                if s == 401 and j.get("status") == "error" and j.get("message") in DENIAL: return self.send(401, {"error": "no_session"})
                return self.send(502, {"error": "unrecognized"})
            if u.path == "/logout":
                s, _, _ = call("POST", "/api/signout", cookie=self.sid())
                return self.send(200, {"logged_out": True}) if s in (200, 204) else self.send(502, {"error": "unrecognized"})
            if u.path == "/disable_user" and user in USERS:
                s, _, j = call("POST", "/api/signin", {"username": "admin", "password": secret("admin_password")})
                tok = (j.get("data") or {}).get("token") if s == 200 else None
                s2, _, _ = call("DELETE", "/api/users?param=" + urllib.parse.quote(user), token=tok) if tok else (None, None, None)
                return self.send(200, {"ok": True}) if s2 == 200 else self.send(502, {"error": "unrecognized"})
            self.send(404, {"error": "not_found"})
        except (OSError, http.client.HTTPException):
            self.send(502, {"error": "unrecognized"})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
