#!/usr/bin/env bash
# Exercise the host side of the runners against a stand-in for the container engine.
#
# Usage:  bash tools/dry_run_runners.sh <empty work folder>
#
# No container is started and no third-party code runs: the stand-in answers every engine command with an exit status,
# and the scripts that would run inside a container are never started. What this shows is what the runners decide on
# the host: which release is skipped, with which exit status; that a pinned image already on the machine is used when
# a pull fails; what the build record says; that a merge refuses a specification that changed after its freeze block.
# It works on a copy of the repository and needs bash, tar and Python. It does not replace a run on a container engine.
set -u
[ $# -eq 1 ] || { echo "usage: bash tools/dry_run_runners.sh <empty work folder>" >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$1"
if [ -e "$TMP" ] && [ -n "$(ls -A "$TMP" 2>/dev/null)" ]; then echo "the work folder must be empty" >&2; exit 4; fi
mkdir -p "$TMP/bin" "$TMP/repo"
TMP="$(cd "$TMP" && pwd)"
(cd "$REPO" && tar -cf - --exclude=.git --exclude=__pycache__ .) | (cd "$TMP/repo" && tar -xf -)
# Some systems have python but no working python3.
if ! python3 --version > /dev/null 2>&1; then
  printf '#!/bin/sh\nexec python "$@"\n' > "$TMP/bin/python3"; chmod +x "$TMP/bin/python3"
fi
cat > "$TMP/engine" <<'EOF'
#!/bin/sh
# Stand-in for the container engine. The tool image counts as present; the last argument of "image inspect" is the image.
for LAST in "$@"; do :; done
case "$1" in
  version) echo "stand-in" ;;
  pull) echo "simulated: registry not reachable"; exit "${PULL_EXIT:-0}" ;;
  image) case "$LAST" in *library/python@*) exit 0 ;; *) exit "${INSPECT_EXIT:-0}" ;; esac ;;
  build) echo "#1 [internal] load build definition"; echo "#5 CACHED"; exit 0 ;;
  *) echo "$*" >> "$ENGINE_LOG"; exit 0 ;;
esac
EOF
chmod +x "$TMP/engine"
export PATH="$TMP/bin:$PATH" CONTAINER_ENGINE="$TMP/engine" ENGINE_LOG="$TMP/engine_calls.txt"
cd "$TMP/repo"

echo "== freeze block for the third application series"
bash checks/run/freeze.sh applications_third "dry run against a stand-in engine" > /dev/null; echo "freeze_exit=$?"

echo "== every pull fails and the application images are not on the machine: expected status 3, two releases skipped"
PULL_EXIT=1 INSPECT_EXIT=1 bash checks/run/applications.sh third "$TMP/out_skip" boot T5 > "$TMP/skip.stdout" 2> "$TMP/skip.stderr"; echo "status=$?"
echo "releases reported as not pulled: $(grep -c '^Could not pull' "$TMP/out_skip/environment_host.txt")"
sed "s|$TMP|<work>|g" "$TMP/skip.stderr"

echo "== every pull fails and the images are on the machine: expected status 0, nothing skipped"
: > "$ENGINE_LOG"
PULL_EXIT=1 INSPECT_EXIT=0 bash checks/run/applications.sh third "$TMP/out_boot" boot T5 > "$TMP/boot.stdout" 2> "$TMP/boot.stderr"; echo "status=$?"
tail -n 1 "$TMP/out_boot/container_pull_T5_fixed.txt"
echo "log heads named by run: $(ls "$TMP/out_boot" | grep -c 'app_log_head_T5_.*_BOOT_run_01.txt')"
echo "engine calls: network create $(grep -c '^network create' "$ENGINE_LOG"), volume create $(grep -c '^volume create' "$ENGINE_LOG"), run $(grep -c '^run ' "$ENGINE_LOG"), rm $(grep -c '^rm -f' "$ENGINE_LOG"), volume rm $(grep -c '^volume rm' "$ENGINE_LOG"), network rm $(grep -c '^network rm' "$ENGINE_LOG")"
echo "calls with --privileged, host network or a published port: $(grep -c -- '--privileged\|--network host\| -p ' "$ENGINE_LOG")"

echo "== build record of the distribution images: expected ten lines with steps_from_cache=1 of 1"
bash checks/run/distributions.sh build "$TMP/out_build" > /dev/null 2>&1; echo "status=$?"
echo "build lines: $(grep -c 'build_exit=0 steps_from_cache=1 of 1$' "$TMP/out_build/build_records.txt"), pull lines: $(grep -c 'pull_exit=0' "$TMP/out_build/build_records.txt")"
if [ -e "$TMP/out_build/results" ]; then echo "results folder present"; else echo "no results folder"; fi

echo "== merge with a matching freeze block: the freeze check passes and the attempts are named by their folders"
mkdir -p "$TMP/a/results/T5.grant_withdrawn/vulnerable/run_01" "$TMP/b/results/T5.grant_withdrawn/fixed/run_01"
echo one > "$TMP/a/results/T5.grant_withdrawn/vulnerable/run_01/x.txt"; echo two > "$TMP/b/results/T5.grant_withdrawn/fixed/run_01/y.txt"
bash checks/run/merge.sh third "$TMP/out_merge" "$TMP/a" "$TMP/b" > "$TMP/merge.stdout" 2> "$TMP/merge.stderr"
echo "status=$? (the evaluation needs a real engine, so a status other than 0 is expected here)"
echo "frozen files found unchanged: $(grep -c ': OK' "$TMP/out_merge/freeze_check.txt"); $(grep 'merge_exit' "$TMP/out_merge/environment_host.txt")"
python3 -c "import json,sys; r=json.load(open(sys.argv[1])); print([a['results'] for a in r['attempts']], r['files'])" "$TMP/out_merge/merge_record.json"

echo "== merge after the specification was changed: expected status 5, nothing merged"
printf ' ' >> checks/phase3c/SPEC_CELLS_3C.json
bash checks/run/merge.sh third "$TMP/out_merge2" "$TMP/a" "$TMP/b" > "$TMP/merge2.stdout" 2> "$TMP/merge2.stderr"; echo "status=$?"
sed "s|$TMP|<work>|g" "$TMP/merge2.stderr"
if [ -e "$TMP/out_merge2/merge_record.json" ]; then echo "merge ran"; else echo "nothing was merged"; fi
