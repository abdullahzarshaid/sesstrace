"""Synthetic OAuth 2.0 / OpenID Connect deployment used by every mechanism.

Four real HTTP servers on 127.0.0.1 (ephemeral ports), standard library only:

  IdP  OpenID Provider: /login, /authorize, /token (authorization_code and
       refresh_token grants), /revoke (RFC 7009), /introspect (RFC 7662),
       /logout (OpenID Connect RP-Initiated Logout 1.0), /password (credential
       change), plus OpenID Connect Back-Channel Logout 1.0 delivery to RPs.
  RP1, RP2  two relying parties sharing the IdP: /login, /callback, /profile
       (protected), /tokens (harness helper), /logout, /backchannel_logout.
  RS   resource server: /api/data protected by Bearer tokens validated by
       introspection at the IdP, with an introspection cache.

ONE flag per mechanism selects the vulnerable behaviour; everything else is
identical between the vulnerable and the fixed variant. The flags are:

  M1  RP /logout clears the cookie but keeps the server-side session record
  M2  IdP session termination does not revoke the tokens bound to the session
  M3  IdP /revoke acknowledges (200) but does not invalidate the refresh token
  M4  RP ignores the back-channel logout token it receives from the IdP
  M5  RS reuses a cached introspection decision (TTL 300 s) after revocation
  M6  IdP /password changes the credential but leaves the user's other
      sessions and their tokens alive

Identifiers (session ids, codes, tokens, HMAC key) are drawn from a seeded PRNG
so a scenario's artifact prefixes are reproducible run to run. This is a
laboratory, not a production design: the PRNG is not a CSPRNG on purpose.
"""
import base64
import hashlib
import hmac
import json
import random
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MECHANISM_FLAGS = ("M1", "M2", "M3", "M4", "M5", "M6")
USERS = {"alice": "correct-horse", "bob": "battery-staple"}
TOKEN_LIFETIME_S = 600
INTROSPECTION_CACHE_TTL_S = 300


class Flags:
    """The set of mechanisms implemented in their VULNERABLE form."""

    def __init__(self, vulnerable=()):
        self.vulnerable = set(vulnerable)
        unknown = self.vulnerable - set(MECHANISM_FLAGS)
        if unknown:
            raise ValueError("unknown mechanism flag(s): %s" % sorted(unknown))

    def __contains__(self, mechanism_id):
        return mechanism_id in self.vulnerable


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Ids:
    """Seeded identifier source shared by one deployment."""

    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.lock = threading.Lock()

    def hex(self, nbytes):
        with self.lock:
            return self.rng.getrandbits(nbytes * 8).to_bytes(nbytes, "big").hex()

    def bytes(self, nbytes):
        return bytes.fromhex(self.hex(nbytes))


# --------------------------------------------------------------------------- IdP
class IdPState:
    def __init__(self, flags, ids, trace):
        self.flags, self.ids, self.trace = flags, ids, trace
        self.key = ids.bytes(32)
        self.users = dict(USERS)
        self.idp_sessions = {}   # idp_sid(cookie) -> {"sub", "sid", "rps": {client_id: backchannel_uri}}
        self.codes = {}          # code -> {"sub", "sid", "client_id"}
        self.refresh = {}        # refresh_token -> {"sub", "sid", "client_id", "revoked"}
        self.access_index = {}   # jti -> {"sub", "sid", "client_id", "exp", "revoked"}
        self.clients = {}        # client_id -> {"secret", "redirect_uri", "backchannel_uri"}
        self.lock = threading.RLock()

    def sign(self, payload):
        h = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        p = _b64(json.dumps(payload).encode())
        sig = _b64(hmac.new(self.key, ("%s.%s" % (h, p)).encode(), hashlib.sha256).digest())
        return "%s.%s.%s" % (h, p, sig)

    def verify(self, tok):
        try:
            h, p, s = tok.split(".")
            exp = _b64(hmac.new(self.key, ("%s.%s" % (h, p)).encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(exp, s):
                return None
            return json.loads(_unb64(p))
        except Exception:
            return None

    def issue_tokens(self, sub, sid, client_id):
        jti = self.ids.hex(8)
        now = int(time.time())
        access = self.sign({"iss": "lab-idp", "sub": sub, "sid": sid, "aud": "lab-rs",
                            "jti": jti, "iat": now, "exp": now + TOKEN_LIFETIME_S})
        self.access_index[jti] = {"sub": sub, "sid": sid, "client_id": client_id,
                                  "exp": now + TOKEN_LIFETIME_S, "revoked": False}
        rt = self.ids.hex(16)
        self.refresh[rt] = {"sub": sub, "sid": sid, "client_id": client_id, "revoked": False}
        id_token = self.sign({"iss": "lab-idp", "sub": sub, "sid": sid, "aud": client_id,
                              "iat": now, "exp": now + TOKEN_LIFETIME_S})
        return {"access_token": access, "token_type": "Bearer", "expires_in": TOKEN_LIFETIME_S,
                "refresh_token": rt, "id_token": id_token}

    def terminate_session(self, sid):
        """End one IdP session: drop the session record, revoke the tokens bound
        to it (unless M2 is vulnerable) and deliver back-channel logout to every
        RP that logged in under it."""
        rps, sub = {}, None
        for cookie_sid, s in list(self.idp_sessions.items()):
            if s["sid"] == sid:
                rps, sub = s["rps"], s["sub"]
                del self.idp_sessions[cookie_sid]
        # ---- M2 flag ---------------------------------------------------------
        if "M2" not in self.flags:                       # FIXED: revoke bound tokens
            for a in self.access_index.values():
                if a["sid"] == sid:
                    a["revoked"] = True
            for r in self.refresh.values():
                if r["sid"] == sid:
                    r["revoked"] = True
        # VULNERABLE M2: the IdP session is gone but its tokens stay valid.
        # ---- OpenID Connect Back-Channel Logout 1.0 delivery (always sent) ---
        for client_id, uri in rps.items():
            logout_token = self.sign({"iss": "lab-idp", "sub": sub, "aud": client_id,
                                      "iat": int(time.time()), "jti": self.ids.hex(8), "sid": sid,
                                      "events": {"http://schemas.openid.net/event/backchannel-logout": {}}})
            self.trace.http("POST", uri, data={"logout_token": logout_token},
                            actor="IdP->%s" % client_id, note="back-channel logout delivery")

    def route(self, method, path, q, body, cookies, headers):
        with self.lock:
            return self._route(method, path, q, body, cookies)

    def _route(self, method, path, q, body, cookies):
        if path == "/login" and method == "POST":
            if self.users.get(body.get("username")) != body.get("password"):
                return 401, {"error": "invalid_credentials"}, {}
            cookie_sid, sid = self.ids.hex(16), self.ids.hex(8)
            self.idp_sessions[cookie_sid] = {"sub": body["username"], "sid": sid, "rps": {}}
            return 200, {"ok": True, "sid": sid}, {"Set-Cookie": "idp_sid=%s; HttpOnly; Path=/" % cookie_sid}

        if path == "/authorize" and method == "GET":
            sess = self.idp_sessions.get(cookies.get("idp_sid", ""))
            if not sess:
                return 401, {"error": "login_required"}, {}
            cid = q.get("client_id")
            c = self.clients.get(cid)
            if not c or q.get("redirect_uri") != c["redirect_uri"]:
                return 400, {"error": "invalid_client"}, {}
            code = self.ids.hex(12)
            self.codes[code] = {"sub": sess["sub"], "sid": sess["sid"], "client_id": cid}
            sess["rps"][cid] = c["backchannel_uri"]
            return 302, {}, {"Location": "%s?code=%s&state=%s" % (c["redirect_uri"], code, q.get("state", ""))}

        if path == "/token" and method == "POST":
            cid, sec = body.get("client_id"), body.get("client_secret")
            c = self.clients.get(cid)
            if not c or c["secret"] != sec:
                return 401, {"error": "invalid_client"}, {}
            g = body.get("grant_type")
            if g == "authorization_code":
                cd = self.codes.pop(body.get("code", ""), None)
                if not cd or cd["client_id"] != cid:
                    return 400, {"error": "invalid_grant"}, {}
                return 200, self.issue_tokens(cd["sub"], cd["sid"], cid), {}
            if g == "refresh_token":
                r = self.refresh.get(body.get("refresh_token", ""))
                if not r or r["client_id"] != cid:
                    return 400, {"error": "invalid_grant"}, {}
                if r["revoked"]:
                    return 400, {"error": "invalid_grant", "error_description": "refresh token revoked"}, {}
                return 200, self.issue_tokens(r["sub"], r["sid"], cid), {}
            return 400, {"error": "unsupported_grant_type"}, {}

        if path == "/revoke" and method == "POST":                  # RFC 7009
            c = self.clients.get(body.get("client_id"))
            if not c or c["secret"] != body.get("client_secret"):
                return 401, {"error": "invalid_client"}, {}
            tok, hint = body.get("token", ""), body.get("token_type_hint", "")
            if hint == "refresh_token" or tok in self.refresh:
                r = self.refresh.get(tok)
                # ---- M3 flag -------------------------------------------------
                if r is not None and "M3" not in self.flags:     # FIXED: invalidate
                    r["revoked"] = True
                    # Lab policy also revokes access tokens from the grant.
                    # RFC 7009 requirements depend on direction/token support;
                    # this is not a universal symmetric revocation rule.
                    for a in self.access_index.values():
                        if a["sid"] == r["sid"] and a["client_id"] == r["client_id"]:
                            a["revoked"] = True
                # VULNERABLE M3: acknowledge with 200 but leave the token usable.
                return 200, {}, {}
            p = self.verify(tok)
            if p and p.get("jti") in self.access_index:
                self.access_index[p["jti"]]["revoked"] = True
            return 200, {}, {}                                      # RFC 7009: 200 even if unknown

        if path == "/introspect" and method == "POST":              # RFC 7662
            p = self.verify(body.get("token", ""))
            if not p:
                return 200, {"active": False}, {}
            a = self.access_index.get(p.get("jti"), {})
            active = bool(a) and not a.get("revoked") and p.get("exp", 0) > time.time()
            return 200, {"active": active, "sub": p.get("sub"), "sid": p.get("sid")}, {}

        if path == "/logout" and method == "GET":                   # RP-Initiated Logout 1.0
            p = self.verify(q.get("id_token_hint", "")) or {}
            sid = p.get("sid")
            if sid is None:
                sess = self.idp_sessions.get(cookies.get("idp_sid", ""))
                sid = sess["sid"] if sess else None
            if sid:
                self.terminate_session(sid)
            return 200, {"logged_out": True}, {"Set-Cookie": "idp_sid=; Max-Age=0; Path=/"}

        if path == "/password" and method == "POST":                # credential change
            sess = self.idp_sessions.get(cookies.get("idp_sid", ""))
            if not sess:
                return 401, {"error": "login_required"}, {}
            sub = sess["sub"]
            if self.users.get(sub) != body.get("current_password") or not body.get("new_password"):
                return 400, {"error": "invalid_request"}, {}
            self.users[sub] = body["new_password"]
            terminated = 0
            # ---- M6 flag ---------------------------------------------------
            if "M6" not in self.flags:                   # FIXED: end every OTHER session of this user
                others = {s["sid"] for s in self.idp_sessions.values()
                          if s["sub"] == sub and s["sid"] != sess["sid"]}
                for other_sid in sorted(others):
                    self.terminate_session(other_sid)
                    terminated += 1
            # VULNERABLE M6: the credential changes; other sessions and their tokens live on.
            return 200, {"changed": True, "other_sessions_terminated": terminated}, {}

        return 404, {"error": "not_found"}, {}


# --------------------------------------------------------------------------- RP
class RPState:
    def __init__(self, name, flags, ids, trace, idp_base, client_id, secret):
        self.name, self.flags, self.ids, self.trace = name, flags, ids, trace
        self.idp, self.cid, self.secret = idp_base, client_id, secret
        self.sessions = {}   # rp_sid -> {"sub", "sid", "id_token", "access", "refresh"}
        self.base = None
        # No lock: an RP makes outgoing calls to the IdP (/token, /logout) that
        # can in turn call back into this RP (back-channel logout). The harness
        # drives every scenario sequentially, so the handler needs no mutex.

    def route(self, method, path, q, body, cookies, headers):
        if path == "/login":
            url = ("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=xyz"
                   % (self.idp, self.cid, urllib.parse.quote(self.base + "/callback")))
            return 302, {}, {"Location": url}

        if path == "/callback":
            tok = self.trace.http("POST", self.idp + "/token",
                                  data={"grant_type": "authorization_code", "code": q.get("code", ""),
                                        "client_id": self.cid, "client_secret": self.secret},
                                  actor=self.name, note="authorization-code exchange").json()
            if "id_token" not in tok:
                return 401, {"error": "token_exchange_failed"}, {}
            claims = json.loads(_unb64(tok["id_token"].split(".")[1]))
            rsid = self.ids.hex(16)
            self.sessions[rsid] = {"sub": claims["sub"], "sid": claims["sid"], "id_token": tok["id_token"],
                                   "access": tok["access_token"], "refresh": tok["refresh_token"]}
            return 200, {"logged_in": True, "rp": self.name}, {"Set-Cookie": "rp_sid=%s; HttpOnly; Path=/" % rsid}

        if path == "/profile":                                      # protected operation
            sess = self.sessions.get(cookies.get("rp_sid", ""))
            if not sess:
                return 401, {"error": "no_session"}, {}
            return 200, {"rp": self.name, "sub": sess["sub"]}, {}

        if path == "/tokens":                                       # harness helper only
            sess = self.sessions.get(cookies.get("rp_sid", ""))
            if not sess:
                return 401, {"error": "no_session"}, {}
            return 200, {"access": sess["access"], "refresh": sess["refresh"], "id_token": sess["id_token"]}, {}

        if path == "/logout":
            rsid = cookies.get("rp_sid", "")
            sess = self.sessions.get(rsid)
            idh = sess["id_token"] if sess else ""
            # ---- M1 flag ---------------------------------------------------
            if "M1" not in self.flags:                    # FIXED: destroy the server-side record
                self.sessions.pop(rsid, None)
            # VULNERABLE M1: only the cookie is cleared; the session record survives.
            if q.get("federated", "1") == "1" and idh:
                self.trace.http("GET", "%s/logout?id_token_hint=%s" % (self.idp, idh),
                                actor=self.name, note="RP-initiated logout at the IdP")
            return 200, {"logged_out": True}, {"Set-Cookie": "rp_sid=; Max-Age=0; Path=/"}

        if path == "/backchannel_logout" and method == "POST":
            # ---- M4 flag -----------------------------------------------------
            if "M4" in self.flags:                        # VULNERABLE: accept and ignore
                return 200, {"ignored": True}, {}
            # FIXED: terminate every local session bound to the logout token's sid.
            try:
                p = json.loads(_unb64(body.get("logout_token", "").split(".")[1]))
            except Exception:
                return 400, {"error": "invalid_request"}, {}
            for k, v in list(self.sessions.items()):
                if v["sid"] == p.get("sid"):
                    del self.sessions[k]
            return 200, {"terminated": True}, {}

        return 404, {"error": "not_found"}, {}


# --------------------------------------------------------------------------- RS
class RSState:
    def __init__(self, flags, trace, idp_base):
        self.flags, self.trace, self.idp = flags, trace, idp_base
        self.cache = {}   # token -> (introspection result, cached_at)
        # ---- M5 flag ---------------------------------------------------------
        # FIXED: TTL 0, every request is introspected. VULNERABLE: a cached
        # "active" decision is reused for up to 300 s, outliving revocation.
        self.cache_ttl = INTROSPECTION_CACHE_TTL_S if "M5" in flags else 0
        self.lock = threading.RLock()

    def route(self, method, path, q, body, cookies, headers):
        with self.lock:
            if path == "/api/data":
                auth = headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return 401, {"error": "missing_token"}, {}
                tok = auth[7:]
                hit = self.cache.get(tok)
                if hit and time.time() - hit[1] < self.cache_ttl:
                    res, src = hit[0], "cache"
                else:
                    res = self.trace.http("POST", self.idp + "/introspect", data={"token": tok},
                                          actor="RS", note="token introspection").json()
                    self.cache[tok] = (res, time.time())
                    src = "introspection"
                if not res.get("active"):
                    return 401, {"error": "invalid_token", "decision_source": src}, {}
                return 200, {"data": "report", "sub": res.get("sub"), "decision_source": src}, {}
            return 404, {"error": "not_found"}, {}


# --------------------------------------------------------------------------- HTTP plumbing
def _make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _handle(self, method):
            # Correlate nested calls with their actual incoming initiating request.
            try:
                state.trace.context.request_id = int(self.headers.get("X-SessTrace-Request", "0")) or None
            except ValueError:
                state.trace.context.request_id = None
            u = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            body = dict(urllib.parse.parse_qsl(raw.decode())) if raw else {}
            cookies = {}
            for part in self.headers.get("Cookie", "").split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k] = v
            status, payload, hdrs = state.route(method, u.path, q, body, cookies, self.headers)
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return Handler


def _start(state):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % port


class Lab:
    """One fresh deployment (IdP + RP1 + RP2 + RS) with a given flag set."""

    def __init__(self, flags, trace, seed=0):
        self.flags, self.trace, self.seed = flags, trace, seed
        self.ids = Ids(seed)
        self.passwords = dict(USERS)          # what the harness believes each user's password is
        self.servers = []
        self.idp_state = IdPState(flags, self.ids, trace)
        srv, self.idp_url = _start(self.idp_state)
        self.servers.append(srv)
        trace.register_host(self.idp_url, "idp")
        self.rs_state = RSState(flags, trace, self.idp_url)
        srv, self.rs_url = _start(self.rs_state)
        self.servers.append(srv)
        trace.register_host(self.rs_url, "rs")
        self.rps = {}
        for name in ("RP1", "RP2"):
            cid, secret = name.lower(), "s3cr3t-" + name
            st = RPState(name, flags, self.ids, trace, self.idp_url, cid, secret)
            srv, url = _start(st)
            self.servers.append(srv)
            st.base = url
            trace.register_host(url, cid)
            self.idp_state.clients[cid] = {"secret": secret, "redirect_uri": url + "/callback",
                                           "backchannel_uri": url + "/backchannel_logout"}
            self.rps[name] = (st, url)

    def close(self):
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()

    def client(self, rp):
        return self.rps[rp][0].cid, self.rps[rp][0].secret

    def rp_url(self, rp):
        return self.rps[rp][1]

    # ---- browser-like helpers (every call is a real HTTP request) ------------
    def idp_login(self, user, actor):
        r = self.trace.http("POST", self.idp_url + "/login",
                            data={"username": user, "password": self.passwords[user]}, actor=actor)
        return r.cookie("idp_sid")

    def sso_login(self, rp, idp_cookie, actor):
        """Authorization-code flow through the browser; returns the RP session cookie."""
        r = self.trace.http("GET", self.rp_url(rp) + "/login", actor=actor)
        r2 = self.trace.http("GET", r.header("Location"), cookies={"idp_sid": idp_cookie}, actor=actor)
        r3 = self.trace.http("GET", r2.header("Location"), actor=actor)
        return r3.cookie("rp_sid")

    def rp_tokens(self, rp, rp_cookie, actor):
        return self.trace.http("GET", self.rp_url(rp) + "/tokens", cookies={"rp_sid": rp_cookie},
                               actor=actor, note="harness helper: read the tokens held by this RP session").json()
