"""SessTrace lifecycle-trace recorder.

One Trace object per scenario (mechanism x variant). Every HTTP request made by
the harness *or* by one lab server to another (RP -> IdP token exchange,
RS -> IdP introspection, IdP -> RP back-channel logout) is recorded as one
numbered step. Artifact bytes and query values are redacted; response values
are restricted to a synthetic schema. This is not a sanitizer for arbitrary
real-system evidence.
"""
import json
import threading
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
from http.client import HTTPException

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def redact(value):
    """Do not export artifact bytes, including short secrets or prefixes."""
    if value is None:
        return None
    return "<redacted>"


class Response:
    def __init__(self, status, headers, body, request_id=None, error=None):
        self.status, self.headers, self.body = status, headers, body
        self.request_id, self.error = request_id, error

    def json(self):
        try:
            return json.loads(self.body or "{}")
        except ValueError:
            return {}

    def cookie(self, name):
        for h, v in self.headers:
            if h.lower() == "set-cookie" and v.startswith(name + "="):
                return v.split(";")[0].split("=", 1)[1]
        return None

    def header(self, name):
        for h, v in self.headers:
            if h.lower() == name.lower():
                return v
        return None


class Trace:
    """Records artifacts and HTTP steps for one scenario."""

    def __init__(self, mechanism_id, variant, seed):
        self.mechanism_id = mechanism_id
        self.variant = variant
        self.seed = seed
        self.steps = []
        self.artifacts = []            # list of dicts (id, type, holder, issued_at_step, value_prefix)
        self._values = {}              # secret value -> artifact id
        self._hosts = {}               # "http://127.0.0.1:port" -> logical host name
        self.phase = "setup"
        self.lock = threading.Lock()
        self.context = threading.local()

    # ---- registration -------------------------------------------------------
    def register_host(self, base_url, logical_name):
        self._hosts[base_url] = logical_name

    def register_artifact(self, kind, holder, value, note=""):
        """Register a secret artifact (cookie value, token) and return its id."""
        with self.lock:
            aid = "A%d" % (len(self.artifacts) + 1)
            self.artifacts.append({
                "id": aid, "type": kind, "holder": holder,
                "issued_at_step": len(self.steps),   # the step that produced it
                "value_prefix": redact(value), "note": note,
                "presented_at_steps": [],
            })
            if value:
                self._values[str(value)] = aid
        return aid

    def artifact_id(self, value):
        return self._values.get(str(value)) if value is not None else None

    def set_phase(self, phase):
        self.phase = phase

    # ---- redaction helpers --------------------------------------------------
    def _logical(self, url):
        u = urllib.parse.urlsplit(url)
        base = "%s://%s" % (u.scheme, u.netloc)
        return self._hosts.get(base, "external"), u.path, u.query

    def _redact_query(self, query):
        out = []
        for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
            aid = self.artifact_id(v)
            safe_key = k if k in {"code", "state", "id_token_hint", "federated", "client_id", "redirect_uri", "scope", "response_type"} else "field"
            out.append("%s=%s" % (safe_key, ("<%s>" % aid) if aid else "<redacted>"))
        return "&".join(out)

    def _presented(self, headers, cookies, data):
        """Return the artifact ids presented in this request, in a stable order."""
        ids = []
        for v in (cookies or {}).values():
            aid = self.artifact_id(v)
            if aid:
                ids.append(aid)
        auth = (headers or {}).get("Authorization", "")
        if auth.startswith("Bearer "):
            aid = self.artifact_id(auth[7:])
            ids.append(aid or "unregistered-bearer")
        for k, v in (data or {}).items():
            if k in ("token", "refresh_token", "logout_token", "id_token_hint", "code"):
                aid = self.artifact_id(v)
                if aid:
                    ids.append(aid)
                elif k == "logout_token":
                    ids.append("logout_token(unregistered)")
        return ids

    def _summarise_body(self, body):
        try:
            obj = json.loads(body or "{}")
        except ValueError:
            return {"body": "<non-json redacted>"}
        if not isinstance(obj, dict):
            return {}
        # Keys alone are not a secrecy boundary: free text/nested data can hold credentials.
        enums = {"error": {"invalid_credentials", "login_required", "invalid_client", "invalid_grant",
                          "unsupported_grant_type", "invalid_request", "not_found", "no_session",
                          "token_exchange_failed", "missing_token", "invalid_token"},
                 "decision_source": {"cache", "introspection"}, "rp": {"RP1", "RP2"},
                 "sub": {"alice", "bob"}, "data": {"report"}, "token_type": {"Bearer"}}
        bool_keys = {"active", "logged_out", "logged_in", "terminated", "ignored", "ok", "changed"}
        out = {}
        for key, allowed in enums.items():
            value = obj.get(key)
            if isinstance(value, str) and value in allowed:
                out[key] = value
        for key in bool_keys:
            if isinstance(obj.get(key), bool):
                out[key] = obj[key]
        # Do not export unknown key names: keys can themselves contain sensitive values.
        out["redacted_field_count"] = len(obj) - len(out)
        return out

    # ---- the instrumented HTTP client --------------------------------------
    def http(self, method, url, data=None, headers=None, cookies=None, actor="client", note=None):
        hdr = dict(headers or {})
        if cookies:
            hdr["Cookie"] = "; ".join("%s=%s" % (k, v) for k, v in cookies.items())
        payload = urllib.parse.urlencode(data).encode() if data is not None else None
        if payload is not None:
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
        host, path, query = self._logical(url)
        presented = self._presented(headers, cookies, data)
        # The step is numbered when the request is SENT, so nested
        # server-to-server calls (RP->IdP, IdP->RP, RS->IdP) appear after the
        # request that caused them: the trace reads in causal order.
        with self.lock:
            step = {
                "step": len(self.steps) + 1,
                "parent_step": getattr(self.context, "request_id", None),
                "phase": self.phase,
                "actor": actor,
                "method": method,
                "host": host,
                "path": path + (("?" + self._redact_query(query)) if query else ""),
                "status": None,
                "artifact_presented": presented[0] if len(presented) == 1 else (presented or None),
                "response": None,
            }
            if note:
                step["note"] = note
            self.steps.append(step)
            for aid in presented:
                for a in self.artifacts:
                    if a["id"] == aid:
                        a["presented_at_steps"].append(step["step"])
        hdr["X-SessTrace-Request"] = str(step["step"])
        req = urllib.request.Request(url, data=payload, headers=hdr, method=method)
        error = None
        try:
            r = _OPENER.open(req, timeout=10)
            status, hs, body = r.status, list(r.getheaders()), r.read().decode()
        except HTTPError as e:
            status, hs, body = e.code, list(e.headers.items()), e.read().decode()
        except (URLError, TimeoutError, OSError, UnicodeError, HTTPException) as e:
            status, hs, body = None, [], "{}"
            error = type(e).__name__  # Never include exception text/URL/credentials.
        with self.lock:
            step["status"] = status
            step["response"] = self._summarise_body(body)
            step["transport_error"] = error
        return Response(status, hs, body, request_id=step["step"], error=error)

    def current_step(self):
        return len(self.steps)
