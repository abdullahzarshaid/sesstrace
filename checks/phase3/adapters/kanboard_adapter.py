#!/usr/bin/env python3
"""Part D adapter for Kanboard (T8). It speaks the contract of phases 1 and 2 and nothing more; it keeps no session table,
caches nothing and decides nothing by itself. Python standard library only.
Usage: python3 kanboard_adapter.py <port> <application request log> ; reads passwords from /secrets, the application is app:80.
sid carries the application's own session cookie KB_SID unchanged. /profile is the user's own profile page
(UserViewController show without user_id), which prints 'Login: <strong>username</strong>'."""
import base64, html, http.client, json, re, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), open(sys.argv[2], "a")
APP, COOKIE = ("app", 80), "KB_SID"
USERS = ("alice", "bob")
NEWPW = {}


def secret(name):
    return open("/secrets/" + name, encoding="utf-8").read().strip()


def password(user):
    return NEWPW.get(user) or secret(user + "_password")


def call(method, path, form=None, sid=None, rpc=None):
    c = http.client.HTTPConnection(*APP, timeout=20)
    h, data = {}, None
    if form is not None: data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    if rpc is not None:
        data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": rpc[0], "params": rpc[1]}).encode(); h["Content-Type"] = "application/json"
        h["Authorization"] = "Basic " + base64.b64encode(("admin:" + secret("admin_password")).encode()).decode()
    if sid: h["Cookie"] = "%s=%s" % (COOKIE, sid)
    c.request(method, path, body=data, headers=h)
    r = c.getresponse(); text = r.read().decode("utf-8", "replace"); c.close()
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(path).query))  # only controller and action are logged, never a token
    LOG.write("%s %s %s %s %s %d\n" % (time.strftime("%H:%M:%S"), method, urllib.parse.urlsplit(path).path, qs.get("controller", "-"), qs.get("action", "-"), r.status)); LOG.flush()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders() if k.lower() != "set-cookie"), [v for k, v in r.getheaders() if k.lower() == "set-cookie"], text


def cookie(set_cookies):
    for v in set_cookies:
        if v.startswith(COOKIE + "="):
            return v.split(";")[0].split("=", 1)[1]


def csrf(text):
    m = re.search(r'name="csrf_token" value="([^"]+)"', text)
    return m.group(1) if m else ""


def to_login(status, headers):
    return status == 302 and ("action=login" in headers.get("location", "") or headers.get("location", "").rstrip("/").endswith("/login"))


def web_login(user, pw):
    s, h, sc, t = call("GET", "/?controller=AuthController&action=login")
    sid0 = cookie(sc)
    s, h, sc, t = call("POST", "/?controller=AuthController&action=check", form={"csrf_token": csrf(t), "username": user, "password": pw}, sid=sid0)
    return (cookie(sc) or sid0) if s == 302 and not to_login(s, h) else None


def rpc(method, params):
    s, _, _, t = call("POST", "/jsonrpc.php", rpc=(method, params))
    return json.loads(t).get("result") if s == 200 else None


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
                s, _, _, _ = call("GET", "/?controller=AuthController&action=login")
                return self.send(200, {"ok": True}) if s == 200 else self.send(503, {"error": "unrecognized"})
            if u.path == "/login" and user in USERS:
                v = web_login(user, password(user))
                return self.send(200, {"logged_in": True}, sid=v) if v else self.send(502, {"error": "unrecognized"})
            if u.path == "/profile":
                s, h, _, t = call("GET", "/?controller=UserViewController&action=show", sid=self.sid())
                m = re.search(r"Login: <strong>([^<]+)</strong>", t) if s == 200 else None
                if m and html.unescape(m.group(1)) in USERS: return self.send(200, {"sub": html.unescape(m.group(1)), "rp": "RP1"})
                if to_login(s, h): return self.send(401, {"error": "no_session"})
                return self.send(502, {"error": "unrecognized"})
            if u.path == "/logout":
                s, h, _, t = call("GET", "/?controller=DashboardController&action=show", sid=self.sid())
                m = re.search(r'href="([^"]*logout[^"]*)"', t) if s == 200 else None
                s2, h2, _, _ = call("GET", html.unescape(m.group(1)), sid=self.sid()) if m else (None, {}, None, None)
                return self.send(200, {"logged_out": True}) if to_login(s2, h2) else self.send(502, {"error": "unrecognized"})
            if u.path == "/change_password" and user in USERS:
                uid = (rpc("getUserByName", [user]) or {}).get("id")
                sid2 = web_login(user, password(user))  # a second, separate login of the user
                new = secret(user + "_new_password")
                s, _, _, t = call("GET", "/?controller=UserCredentialController&action=changePassword&user_id=%s" % uid, sid=sid2)
                form = {"csrf_token": csrf(t), "id": uid, "current_password": password(user), "password": new, "confirmation": new}
                s2, h2, _, _ = call("POST", "/?controller=UserCredentialController&action=savePassword&user_id=%s" % uid, form=form, sid=sid2)
                if s2 == 302 and "UserViewController" in h2.get("location", "") or (s2 == 302 and "/user/" in h2.get("location", "")):
                    NEWPW[user] = new
                    return self.send(200, {"changed": True})
                return self.send(502, {"error": "unrecognized"})
            if u.path == "/disable_user" and user in USERS:
                uid = (rpc("getUserByName", [user]) or {}).get("id")
                return self.send(200, {"ok": True}) if uid and rpc("disableUser", [uid]) is True else self.send(502, {"error": "unrecognized"})
            self.send(404, {"error": "not_found"})
        except (OSError, http.client.HTTPException, ValueError):
            self.send(502, {"error": "unrecognized"})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
