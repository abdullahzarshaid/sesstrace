"""Small HTTP servers that speak the endpoint contract, written for the tests.

They stand in for a target so that the driver and the evaluator can be tested
without any third-party software. Nothing they produce is a result.

SessionStub models a session library behind a host application:

    store       sessions kept on the server; the fixed variant drops a session
                whose idle lifetime has passed
    stateless   the cookie is "<user>.<issue time>"; logout cannot revoke it;
                the fixed variant refuses a cookie older than the lifetime
    pool        sessions kept on the server; /slow_profile writes the session
                back after a delay, which brings a logged-out session back
                unless the variant is fixed

ApplicationStub models a complete application behind an adapter, with the
events password change and account disabled.
"""
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit


class _Handler(BaseHTTPRequestHandler):
    """Routes GET requests to the stub object stored on the server."""

    def log_message(self, *args):
        pass

    def session_id(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sid":
                return value
        return None

    def reply(self, status, body, cookie=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", "sid=%s; Path=/; HttpOnly" % cookie)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlsplit(self.path)
        query = dict(parse_qsl(url.query))
        if url.path == "/ready":
            return self.reply(200, {"ok": True})
        route = getattr(self.server.stub, "on_" + url.path.strip("/"), None)
        if route is None:
            return self.reply(404, {"error": "not_found"})
        return self.reply(*route(self.session_id(), query))


class _Stub:
    def __init__(self):
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.stub = self
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


NO_SESSION = (401, {"error": "no_session"})


class SessionStub(_Stub):
    def __init__(self, kind, fixed, lifetime=1, break_login_after=None, slow=1.0, logout_noop=False):
        if kind not in ("store", "stateless", "pool"):
            raise ValueError("unknown stub kind")
        self.kind = kind
        self.fixed = fixed
        self.lifetime = lifetime
        self.break_login_after = break_login_after
        self.slow = slow
        self.logout_noop = logout_noop
        self.sessions = {}
        self.issued = 0
        self.logins = 0
        super().__init__()

    def _new_id(self):
        self.issued += 1
        return "s%d" % self.issued

    def _user(self, sid):
        now = time.time()
        if not sid:
            return None
        if self.kind == "store":
            session = self.sessions.get(sid)
            if not session:
                return None
            if self.fixed and now >= session["expires"]:
                del self.sessions[sid]
                return None
            session["expires"] = now + self.lifetime
            return session["user"]
        if self.kind == "pool":
            with self.lock:
                return self.sessions.get(sid)
        user, _, issued_at = sid.partition(".")
        if self.fixed and now >= float(issued_at) + self.lifetime:
            return None
        return user

    def on_login(self, sid, query):
        self.logins += 1
        if self.break_login_after is not None and self.logins > self.break_login_after:
            return 500, {"error": "invalid_request"}
        user = query.get("user")
        with self.lock:
            if self.kind == "store":
                new = self._new_id()
                self.sessions[new] = {"user": user, "expires": time.time() + self.lifetime}
            elif self.kind == "pool":
                new = self._new_id()
                self.sessions[new] = user
            else:
                new = "%s.%s" % (user, time.time())
        return 200, {"logged_in": True}, new

    def on_profile(self, sid, query):
        user = self._user(sid)
        return (200, {"sub": user, "rp": "RP1"}) if user else NO_SESSION

    def on_slow_profile(self, sid, query):
        user = self._user(sid)
        if self.kind == "pool":
            time.sleep(self.slow)
            with self.lock:
                # The request read the session before the logout and now writes it back.
                if not self.fixed or sid in self.sessions:
                    self.sessions[sid] = user
        return (200, {"sub": user, "rp": "RP1"}) if user else NO_SESSION

    def on_logout(self, sid, query):
        with self.lock:
            if self.kind in ("store", "pool") and not self.logout_noop:
                self.sessions.pop(sid, None)
            new = None
            if self.kind == "pool":
                new = self._new_id()
                self.sessions[new] = None
        return 200, {"logged_out": True}, new


class ApplicationStub(_Stub):
    def __init__(self, logout_revokes=False, password_revokes=False, disable_revokes=False,
                 lifetime=3600, accept_unknown=False):
        self.logout_revokes = logout_revokes
        self.password_revokes = password_revokes
        self.disable_revokes = disable_revokes
        self.lifetime = lifetime
        self.accept_unknown = accept_unknown
        self.sessions = {}
        self.active = {"alice": True, "bob": True}
        super().__init__()

    def _revoke_all(self, user):
        for session in self.sessions.values():
            if session["user"] == user:
                session["live"] = False

    def on_login(self, sid, query):
        user = query.get("user")
        if not self.active.get(user):
            return 502, {"error": "unrecognized"}
        new = secrets.token_hex(8)
        self.sessions[new] = {"user": user, "issued": time.time(), "live": True}
        return 200, {"logged_in": True}, new

    def on_profile(self, sid, query):
        session = self.sessions.get(sid)
        if session is None:
            return (200, {"sub": "alice", "rp": "RP1"}) if self.accept_unknown else NO_SESSION
        if not session["live"] or time.time() - session["issued"] >= self.lifetime:
            return NO_SESSION
        return 200, {"sub": session["user"], "rp": "RP1"}

    def on_logout(self, sid, query):
        if self.logout_revokes and sid in self.sessions:
            self.sessions[sid]["live"] = False
        return 200, {"logged_out": True}

    def on_change_password(self, sid, query):
        if self.password_revokes:
            self._revoke_all(query.get("user"))
        return 200, {"changed": True}

    def on_disable_user(self, sid, query):
        user = query.get("user")
        self.active[user] = False
        if self.disable_revokes:
            self._revoke_all(user)
        return 200, {"ok": True}


class ShareStub(_Stub):
    """A link share per user; deleting the share is the event. The fixed variant then refuses its token."""

    def __init__(self, deleted_share_still_works, accept_unknown=False):
        self.deleted_share_still_works = deleted_share_still_works
        self.accept_unknown = accept_unknown
        self.tokens = {}
        self.deleted = set()
        super().__init__()

    def on_login(self, sid, query):
        user = query.get("user")
        if user in self.deleted:
            return 502, {"error": "unrecognized"}
        new = secrets.token_hex(8)
        self.tokens[new] = user
        return 200, {"logged_in": True}, new

    def on_profile(self, sid, query):
        user = self.tokens.get(sid)
        if user is None:
            return (200, {"sub": "alice", "rp": "RP1"}) if self.accept_unknown else NO_SESSION
        if user in self.deleted and not self.deleted_share_still_works:
            return NO_SESSION
        return 200, {"sub": user, "rp": "RP1"}

    def on_delete_share(self, sid, query):
        self.deleted.add(query.get("user"))
        return 200, {"terminated": True}
