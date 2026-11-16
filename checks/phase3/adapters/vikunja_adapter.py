#!/usr/bin/env python3
"""Part D adapter for Vikunja (T5). It speaks the contract of phases 1 and 2 and nothing more; it keeps no session table,
caches nothing and decides nothing by itself. Python standard library only.
Usage: python3 vikunja_adapter.py <port> <application request log> ; reads passwords from /secrets, the application is app:3456.
sid carries the application's own access token (the JWT returned by POST /api/v1/login) unchanged."""
import http.client, json, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), open(sys.argv[2], "a")
APP = ("app", 3456)
DENIAL = "missing, malformed, expired or otherwise invalid token provided"
USERS = ("alice", "bob")
NEWPW = {}


def secret(name):
    return open("/secrets/" + name, encoding="utf-8").read().strip()


def password(user):
    return NEWPW.get(user) or secret(user + "_password")


def call(method, path, body=None, bearer=None):
    c = http.client.HTTPConnection(*APP, timeout=20)
    h = {}
    data = json.dumps(body).encode() if body is not None else None
    if data is not None: h["Content-Type"] = "application/json"
    if bearer: h["Authorization"] = "Bearer " + bearer
    c.request(method, path, body=data, headers=h)
    r = c.getresponse(); raw = r.read(); c.close()
    LOG.write("%s %s %s %d\n" % (time.strftime("%H:%M:%S"), method, path.split("?")[0], r.status)); LOG.flush()
    try:
        j = json.loads(raw or b"{}")
    except ValueError:
        j = {}
    return r.status, j if isinstance(j, dict) else {}


def token_login(user):
    s, j = call("POST", "/api/v1/login", {"username": user, "password": password(user), "long_token": False})
    return j.get("token") if s == 200 else None


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
            if u.path == "/login" and user in USERS:
                t = token_login(user)
                return self.send(200, {"logged_in": True}, sid=t) if t else self.send(502, {"error": "unrecognized"})
            if u.path == "/profile":
                s, j = call("GET", "/api/v1/user", bearer=self.sid())
                if s == 200 and j.get("username") in USERS: return self.send(200, {"sub": j["username"], "rp": "RP1"})
                if s == 401 and j.get("message") == DENIAL: return self.send(401, {"error": "no_session"})
                return self.send(502, {"error": "unrecognized"})
            if u.path == "/logout":
                s, _ = call("POST", "/api/v1/user/logout", bearer=self.sid())
                return self.send(200, {"logged_out": True}) if s == 200 else self.send(502, {"error": "unrecognized"})
            if u.path == "/change_password" and user in USERS:
                t = token_login(user)  # a second, separate login of the user
                new = secret(user + "_new_password")
                s, _ = call("POST", "/api/v1/user/password", {"old_password": password(user), "new_password": new}, bearer=t) if t else (None, None)
                if s == 200:
                    NEWPW[user] = new
                    return self.send(200, {"changed": True})
                return self.send(502, {"error": "unrecognized"})
            self.send(404, {"error": "not_found"})
        except (OSError, http.client.HTTPException):
            self.send(502, {"error": "unrecognized"})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
