#!/usr/bin/env python3
"""Part D adapter for Directus (T7). It speaks the contract of phases 1 and 2 and nothing more; it keeps no session table,
caches nothing and decides nothing by itself. Python standard library only.
Usage: python3 directus_adapter.py <port> <application request log> ; reads passwords from /secrets, the application is app:8055.
sid carries the application's own session cookie directus_session_token unchanged."""
import http.client, json, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), open(sys.argv[2], "a")
APP, COOKIE = ("app", 8055), "directus_session_token"
DENIAL = {"INVALID_CREDENTIALS", "INVALID_TOKEN", "TOKEN_EXPIRED"}
EMAIL = {"alice": "alice@example.com", "bob": "bob@example.com"}
NEWPW = {}


def secret(name):
    return open("/secrets/" + name, encoding="utf-8").read().strip()


def password(user):
    return NEWPW.get(user) or secret(user + "_password")


def call(method, path, body=None, cookie=None, bearer=None):
    c = http.client.HTTPConnection(*APP, timeout=20)
    h = {}
    data = json.dumps(body).encode() if body is not None else None
    if data is not None: h["Content-Type"] = "application/json"
    if cookie: h["Cookie"] = "%s=%s" % (COOKIE, cookie)
    if bearer: h["Authorization"] = "Bearer " + bearer
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


def error_code(j):
    try:
        return j["errors"][0]["extensions"]["code"]
    except (KeyError, IndexError, TypeError):
        return None


def json_login(email, pw):
    s, _, j = call("POST", "/auth/login", {"email": email, "password": pw})
    return (j.get("data") or {}).get("access_token") if s == 200 else None


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
                s, _, _ = call("GET", "/server/health")
                return self.send(200, {"ok": True}) if s == 200 else self.send(503, {"error": "unrecognized"})
            if u.path == "/login" and user in EMAIL:
                s, h, _ = call("POST", "/auth/login", {"email": EMAIL[user], "password": password(user), "mode": "session"})
                v = set_cookie(h, COOKIE)
                return self.send(200, {"logged_in": True}, sid=v) if s == 200 and v else self.send(502, {"error": "unrecognized"})
            if u.path == "/profile":
                s, _, j = call("GET", "/users/me?fields=email", cookie=self.sid())
                name = {e: n for n, e in EMAIL.items()}.get((j.get("data") or {}).get("email")) if s == 200 else None
                if name: return self.send(200, {"sub": name, "rp": "RP1"})
                if s == 401 and error_code(j) in DENIAL: return self.send(401, {"error": "no_session"})
                return self.send(502, {"error": "unrecognized"})
            if u.path == "/logout":
                s, _, _ = call("POST", "/auth/logout", {"mode": "session"}, cookie=self.sid())
                return self.send(200, {"logged_out": True}) if s in (200, 204) else self.send(502, {"error": "unrecognized"})
            if u.path == "/change_password" and user in EMAIL:
                token = json_login(EMAIL[user], password(user))  # a second, separate login of the user
                new = secret(user + "_new_password")
                s, _, _ = call("PATCH", "/users/me", {"password": new}, bearer=token) if token else (None, None, None)
                if s in (200, 204):
                    NEWPW[user] = new
                    return self.send(200, {"changed": True})
                return self.send(502, {"error": "unrecognized"})
            if u.path == "/disable_user" and user in EMAIL:
                token = json_login("admin@example.com", secret("admin_password"))
                s, _, j = call("GET", "/users?fields=id&filter[email][_eq]=" + urllib.parse.quote(EMAIL[user]), bearer=token)
                uid = (j.get("data") or [{}])[0].get("id") if s == 200 else None
                s2, _, _ = call("PATCH", "/users/" + uid, {"status": "suspended"}, bearer=token) if uid else (None, None, None)
                return self.send(200, {"ok": True}) if s2 in (200, 204) else self.send(502, {"error": "unrecognized"})
            self.send(404, {"error": "not_found"})
        except (OSError, http.client.HTTPException):
            self.send(502, {"error": "unrecognized"})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
