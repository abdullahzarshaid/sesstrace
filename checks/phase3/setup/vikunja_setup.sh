#!/bin/sh
# Part D set-up for Vikunja (T5): the two ordinary users register through the documented registration API
# (POST /api/v1/register; registration is enabled by default, pkg/config/config.go line 349 or 352). Prints version=.
set -eu
python3 - <<'PY'
import json, sys, urllib.request
APP = "http://app:3456"
def call(path, body=None):
    req = urllib.request.Request(APP + path, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"}, method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, json.loads(r.read() or b"{}")
for u in ("alice", "bob"):
    pw = open("/secrets/%s_password" % u).read().strip()
    s, j = call("/api/v1/register", {"username": u, "email": u + "@example.com", "password": pw})
    print("register", u, s)
s, j = call("/api/v1/info")
print("version=" + str(j.get("version")))
PY
