#!/bin/sh
# Part D. Runs in a throw-away container without network that mounts only the run's secrets volume at /secrets.
# Generates the passwords and keys of one run; they are written nowhere else and the volume is removed after the run.
set -eu
umask 022
python3 - <<'PY'
import secrets
for name in ("admin_password", "alice_password", "bob_password", "alice_new_password", "bob_new_password", "app_key", "app_secret"):
    with open("/secrets/" + name, "w") as f:
        f.write("P3d-" + secrets.token_urlsafe(18) + "\n")
PY
ls /secrets | wc -l
