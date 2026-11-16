#!/bin/sh
# Part D set-up for FUXA (T6): sign in with the administrator the application creates on first start
# (server/runtime/users/usrstorage.js line 112), replace its password with the generated one, and create the two ordinary
# users (group 1) through the user API (POST /api/users with params, server/api/users/index.js line 62). Prints version=.
set -eu
python3 - <<'PY'
import json, urllib.request
APP = "http://app:1881"
def call(method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token: h["x-access-token"] = token
    req = urllib.request.Request(APP + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read()
        return r.status, json.loads(raw) if raw[:1] in (b"{", b"[") else {}
s, j = call("POST", "/api/signin", {"username": "admin", "password": "123456"})
tok = j["data"]["token"]
admin_pw = open("/secrets/admin_password").read().strip()
print("admin password", call("POST", "/api/users", {"params": {"username": "admin", "fullname": "Administrator Account", "password": admin_pw, "groups": -1}}, tok)[0])
s, j = call("POST", "/api/signin", {"username": "admin", "password": admin_pw})
tok = j["data"]["token"]
for u in ("alice", "bob"):
    pw = open("/secrets/%s_password" % u).read().strip()
    st = call("POST", "/api/users", {"params": {"username": u, "fullname": u, "password": pw, "groups": 1}}, tok)[0]; print("create", u, st); assert st == 200
try:
    s, j = call("GET", "/api/version")
    print("version=" + str(j.get("version") if isinstance(j, dict) else j))
except Exception as e:
    print("version=not reported by /api/version (%s)" % type(e).__name__)
PY
