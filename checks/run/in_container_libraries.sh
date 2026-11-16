#!/usr/bin/env bash
# Runs inside the throw-away container of one library target at one revision. Started by libraries.sh.
# Usage: bash /tool/checks/run/in_container_libraries.sh <target> <vulnerable|fixed>
# Mounts: /tool, /ext, /p2, /p3, /k read-only (see common.sh); /out writable.
set -u
TARGET="$1"; REVISION="$2"
SPEC=/tool/checks/phase3/SPEC_CELLS.json
export PYTHONPATH=/tool/src
mkdir -p /out/results /out/logs
E=/out/environment_${TARGET}_${REVISION}.txt
{
  echo "target=$TARGET revision=$REVISION"
  echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  [ -r /etc/os-release ] && . /etc/os-release && echo "os=$PRETTY_NAME"
  echo "python=$(python3 --version 2>&1)"
  if command -v node > /dev/null; then echo "node=$(node --version)"; echo "npm=$(npm --version 2>&1)"; fi
  if command -v ruby > /dev/null; then echo "ruby=$(ruby --version 2>&1)"; echo "gem=$(gem --version 2>&1)"; fi
  if command -v pip > /dev/null; then echo "pip=$(pip --version 2>&1)"; fi
  echo "git=$(git --version)"
  echo "sesstrace=$(python3 -B -m sesstrace --version 2>&1)"
} > "$E" 2>&1

finish() { echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$E"; chmod -R a+rX /out; }

# Nothing is fetched or run unless the frozen files are unchanged inside this container too.
(cd /tool && python3 -B -m sesstrace freeze check . libraries) > "/out/freeze_check_${TARGET}_${REVISION}.txt" 2>&1
FROZEN=$?
echo "freeze_check_exit=$FROZEN" >> "$E"
if [ "$FROZEN" != 0 ]; then echo "freeze_check=failed, nothing was run" >> "$E"; finish; exit 5; fi

python3 /tool/checks/run/plan.py library "$SPEC" "$TARGET" "$REVISION" > /tmp/target.sh
python3 /tool/checks/run/plan.py library-runs "$SPEC" "$TARGET" "$REVISION" > /tmp/runs.txt
. /tmp/target.sh

CHECKOUT=/tmp/checkout/$TARGET/$REVISION
S=/out/results/setup_${TARGET}_${REVISION}.txt
G=/out/logs/git_${TARGET}_${REVISION}.txt
mkdir -p "$(dirname "$CHECKOUT")"
git clone -q "$REPO" "$CHECKOUT" > "$G" 2>&1
if [ "$FETCH_BY_HASH" = 1 ]; then git -C "$CHECKOUT" fetch -q origin "$COMMIT" >> "$G" 2>&1; fi
git -C "$CHECKOUT" checkout -q "$COMMIT" >> "$G" 2>&1
echo "head=$(git -C "$CHECKOUT" rev-parse HEAD 2>/dev/null)" > "$S"
(cd "$CHECKOUT" && bash -c "$INSTALL") > "/out/logs/install_${TARGET}_${REVISION}.txt" 2>&1 < /dev/null
echo "install_exit=$?" >> "$S"

mapfile -t RUNS < /tmp/runs.txt
for LINE in "${RUNS[@]}"; do
  read -r NN CELL PORT HOSTCMD <<< "$LINE"
  L=/out/logs/$CELL/$REVISION/run_$NN
  R=/out/results/$CELL/$REVISION/run_$NN
  mkdir -p "$L" "$R"
  cd "$CHECKOUT"
  bash -c "exec $HOSTCMD" > "$L/host.txt" 2>&1 < /dev/null &
  HOST_PID=$!
  cd /tmp
  READY=0
  for _ in $(seq 1 120); do
    if curl -s -f -m 2 "http://127.0.0.1:$PORT/ready" > /dev/null 2>&1 < /dev/null; then READY=1; break; fi
    sleep 0.5
  done
  echo "run_${NN}_${CELL}_host_ready=$READY" >> "$S"
  if [ "$READY" = 1 ]; then
    python3 -B -m sesstrace run --spec "$SPEC" --entry "$CELL" --revision "$REVISION" \
      --base "http://127.0.0.1:$PORT" --out "$R" > "$L/driver.txt" 2>&1 < /dev/null
    echo "run_${NN}_${CELL}_driver_exit=$?" >> "$S"
  fi
  kill "$HOST_PID" > /dev/null 2>&1
  wait "$HOST_PID" 2> /dev/null
done
(cd "$CHECKOUT" && bash -c "$PKGLIST") > "/out/logs/packages_${TARGET}_${REVISION}.txt" 2>&1 < /dev/null
finish
grep -c 'host_ready=1' "$S" | sed 's/^/host_ready_count=/'
