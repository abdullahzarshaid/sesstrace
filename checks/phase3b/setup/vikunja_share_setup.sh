#!/bin/sh
# Phase 3b set-up for Vikunja (T5.grant_withdrawn): the two users register through the documented registration API, and each
# creates one project (PUT /api/v1/projects) and one read-only link share without password for it
# (PUT /api/v1/projects/:project/shares, permission 0, sharing_type 1). Prints version=.
set -eu
python3 - <<'PY'
import json, urllib.request
APP = "http://app:3456"
def call(method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(APP + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read()
        return r.status, json.loads(raw) if raw else {}
for u in ("alice", "bob"):
    pw = open("/secrets/%s_password" % u).read().strip()
    print("register", u, call("POST", "/api/v1/register", {"username": u, "email": u + "@example.com", "password": pw})[0])
    s, j = call("POST", "/api/v1/login", {"username": u, "password": pw, "long_token": False})
    tok = j["token"]
    s, p = call("PUT", "/api/v1/projects", {"title": "p3b project " + u}, tok)
    print("project", u, s)
    s, sh = call("PUT", "/api/v1/projects/%d/shares" % p["id"], {"permission": 0, "sharing_type": 1}, tok)
    print("share", u, s, "ok" if sh.get("hash") else "no hash")
    assert sh.get("hash")
s, j = call("GET", "/api/v1/info")
print("version=" + str(j.get("version")))
PY
