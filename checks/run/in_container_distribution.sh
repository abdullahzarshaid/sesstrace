#!/bin/sh
# Runs inside the container of one image of the distribution matrix, without network. Started by distributions.sh.
# POSIX sh, so that it also runs on images without bash.
# Usage: sh /tool/checks/run/in_container_distribution.sh <entry id> <python command>
# Mounts: /tool read-only; /out writable.
ID="$1"; PY="$2"; O="/out/$ID"
mkdir -p "$O"
E="$O/environment.txt"
{
  echo "id=$ID"
  echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  grep -E '^(NAME|VERSION|VERSION_ID|ID|PRETTY_NAME)=' /etc/os-release
  echo "python_command=$PY"
  echo "python_path=$(command -v "$PY")"
  echo "python_version=$("$PY" --version 2>&1)"
  echo "libc_python=$("$PY" -c 'import platform; print(platform.libc_ver())' 2>&1)"
  echo "libc_ldd=$( (ldd --version 2>&1 || true) | head -n 2 | tr '\n' ' ')"
  echo "uname=$(uname -a)"
} > "$E" 2>&1

cd /tool && "$PY" -B -m unittest > "$O/unit_tests.txt" 2>&1
echo "unit_tests_exit=$?" >> "$E"

cd /tmp && PYTHONPATH=/tool/src "$PY" -B -m sesstrace lab verify --out "$O/lab" > "$O/lab_verify.txt" 2>&1
echo "lab_verify_exit=$?" >> "$E"

echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$E"
chmod -R a+rX "$O"
