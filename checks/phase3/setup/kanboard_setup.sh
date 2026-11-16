#!/bin/sh
# Part D set-up for Kanboard (T8): sign in with the documented default administrator (admin/admin), replace its password
# with the generated one through the application's password form, and create the two ordinary users through the documented
# JSON-RPC API (createUser). Prints version=.
set -eu
python3 - <<'PY'
import base64, json, re, urllib.parse, http.client
def call(method, path, form=None, sid=None, rpc=None, pw=None):
    c = http.client.HTTPConnection("app", 80, timeout=30); h = {}; data = None
    if form is not None: data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    if rpc is not None:
        data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": rpc[0], "params": rpc[1]}).encode(); h["Content-Type"] = "application/json"
        h["Authorization"] = "Basic " + base64.b64encode(("admin:" + pw).encode()).decode()
    if sid: h["Cookie"] = "KB_SID=" + sid
    c.request(method, path, body=data, headers=h); r = c.getresponse(); t = r.read().decode("utf-8", "replace")
    sc = [v.split(";")[0].split("=", 1)[1] for k, v in r.getheaders() if k.lower() == "set-cookie" and v.startswith("KB_SID=")]
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), (sc[-1] if sc else None), t
csrf = lambda t: re.search(r'name="csrf_token" value="([^"]+)"', t).group(1)
s, h, sid, t = call("GET", "/?controller=AuthController&action=login")
s, h, sid2, t = call("POST", "/?controller=AuthController&action=check", form={"csrf_token": csrf(t), "username": "admin", "password": "admin"}, sid=sid)
sid = sid2 or sid
print("admin login", s); assert s == 302, "admin login failed"
new = open("/secrets/admin_password").read().strip()
s, h, _, t = call("GET", "/?controller=UserCredentialController&action=changePassword&user_id=1", sid=sid)
s, h, _, t = call("POST", "/?controller=UserCredentialController&action=savePassword&user_id=1", form={"csrf_token": csrf(t), "id": "1", "current_password": "admin", "password": new, "confirmation": new}, sid=sid)
print("admin password", s); assert s == 302, "admin password change failed"
for u in ("alice", "bob"):
    pw = open("/secrets/%s_password" % u).read().strip()
    s, h, _, t = call("POST", "/jsonrpc.php", rpc=("createUser", {"username": u, "password": pw}), pw=new)
    ok = bool(json.loads(t).get("result")); print("create", u, s, "ok" if ok else "failed"); assert ok, "createUser failed"
s, h, _, t = call("POST", "/jsonrpc.php", rpc=("getVersion", []), pw=new)
print("version=" + str(json.loads(t).get("result")))
PY
