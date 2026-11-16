#!/bin/sh
# Phase 3b copy of phase3/setup/directus_setup.sh with one addition (marked below) for the second attempt of T7.credential_change.
# Part D set-up for Directus (T7): the administrator comes from the documented ADMIN_EMAIL and ADMIN_PASSWORD settings at
# bootstrap; a role with app access but no admin access and the two users are created through the documented REST API
# (POST /roles, POST /users). Prints version=.
set -eu
python3 - <<'PY'
import json, urllib.request
APP = "http://app:8055"
def call(method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(APP + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return r.status, json.loads(raw) if raw else {}
s, j = call("POST", "/auth/login", {"email": "admin@example.com", "password": open("/secrets/admin_password").read().strip()})
tok = j["data"]["access_token"]
s, j = call("POST", "/roles", {"name": "Users", "app_access": True, "admin_access": False}, tok)
role = j["data"]["id"]
# phase 3b addition: let the role change the own password (documented permission API, POST /permissions; $CURRENT_USER rule)
s, j = call("POST", "/permissions", {"role": role, "collection": "directus_users", "action": "update", "permissions": {"id": {"_eq": "$CURRENT_USER"}}, "fields": ["password"]}, tok)
print("permission update own password", s)
for u in ("alice", "bob"):
    pw = open("/secrets/%s_password" % u).read().strip()
    print("create", u, call("POST", "/users", {"email": u + "@example.com", "password": pw, "role": role, "status": "active"}, tok)[0])
s, j = call("GET", "/server/info", token=tok)
print("version=" + str((j.get("data") or {}).get("version")))
PY
