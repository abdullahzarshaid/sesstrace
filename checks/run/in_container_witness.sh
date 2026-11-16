#!/usr/bin/env bash
# Runs inside the throw-away container of one witness cell at one revision. Started by witness.sh.
# Usage: bash /tool/checks/run/in_container_witness.sh <cell, for example T1.lifetime> <vulnerable|fixed>
# Mounts: /tool, /ext, /p2, /p3, /k read-only (see common.sh); /out writable.
set -u
CELL="$1"; REVISION="$2"
TARGET="${CELL%%.*}"
SPEC=/tool/checks/phase3/SPEC_CELLS.json
WITNESS=/tool/checks/phase3/SPEC_WITNESS.json
export PYTHONPATH=/tool/src
mkdir -p /out/results /out/logs /out/raw /out/counts
E=/out/environment_${CELL}_${REVISION}.txt
{
  echo "cell=$CELL revision=$REVISION"
  echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  [ -r /etc/os-release ] && . /etc/os-release && echo "os=$PRETTY_NAME"
  echo "python=$(python3 --version 2>&1)"
  if command -v node > /dev/null; then echo "node=$(node --version)"; fi
  if command -v ruby > /dev/null; then echo "ruby=$(ruby --version 2>&1)"; fi
  echo "sesstrace=$(python3 -B -m sesstrace --version 2>&1)"
} > "$E" 2>&1
finish() { echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$E"; chmod -R a+rX /out; }

(cd /tool && python3 -B -m sesstrace freeze check . witness) > "/out/freeze_check_${CELL}_${REVISION}.txt" 2>&1
FROZEN=$?
echo "freeze_check_exit=$FROZEN" >> "$E"
if [ "$FROZEN" != 0 ]; then echo "freeze_check=failed, nothing was run" >> "$E"; finish; exit 5; fi

python3 /tool/checks/run/plan.py witness "$SPEC" "$TARGET" "$REVISION" > /tmp/target.sh
. /tmp/target.sh

CHECKOUT=/tmp/checkout/$TARGET/$REVISION
S=/out/results/setup_${CELL}_${REVISION}.txt
G=/out/logs/git_${CELL}_${REVISION}.txt
mkdir -p "$(dirname "$CHECKOUT")"
git clone -q "$REPO" "$CHECKOUT" > "$G" 2>&1
if [ "$FETCH_BY_HASH" = 1 ]; then git -C "$CHECKOUT" fetch -q origin "$COMMIT" >> "$G" 2>&1; fi
git -C "$CHECKOUT" checkout -q "$COMMIT" >> "$G" 2>&1
echo "head=$(git -C "$CHECKOUT" rev-parse HEAD 2>/dev/null)" > "$S"
(cd "$CHECKOUT" && bash -c "$INSTALL") > "/out/logs/install_${CELL}_${REVISION}.txt" 2>&1 < /dev/null
echo "install_exit=$?" >> "$S"

# The counter is switched on from outside the host file; the host command itself is the one of the cell runs.
RAW=/out/raw/${CELL}_${REVISION}
case "$TARGET" in
  T1|T2) RAW=$RAW.v8; mkdir -p "$RAW"
         COMMAND="NODE_V8_COVERAGE=$RAW NODE_OPTIONS='--require /p3/witness/node_preload.js' $HOSTCMD" ;;
  T3)    RAW=$RAW.trace.json
         COMMAND="python3 /p3/witness/python_trace_run.py $RAW ${HOSTCMD#python3 }" ;;
  T4)    RAW=$RAW.coverage.json
         COMMAND="WITNESS_OUT=$RAW RUBYOPT=-r/p3/witness/ruby_coverage.rb $HOSTCMD" ;;
  *)     echo "no line counter is set up for $TARGET" >> "$E"; finish; exit 6 ;;
esac
echo "witness_command=$COMMAND" >> "$S"
R=/out/results/$CELL/$REVISION/witness
L=/out/logs/$CELL/$REVISION/witness
mkdir -p "$R" "$L"
cd "$CHECKOUT"
bash -c "exec env $COMMAND" > "$L/host.txt" 2>&1 < /dev/null &
HOST_PID=$!
cd /tmp
READY=0
for _ in $(seq 1 240); do
  if curl -s -f -m 2 "http://127.0.0.1:$PORT/ready" > /dev/null 2>&1 < /dev/null; then READY=1; break; fi
  sleep 0.5
done
echo "host_ready=$READY" >> "$S"
if [ "$READY" = 1 ]; then
  python3 -B -m sesstrace run --spec "$SPEC" --entry "$CELL" --revision "$REVISION" \
    --base "http://127.0.0.1:$PORT" --out "$R" > "$L/driver.txt" 2>&1 < /dev/null
  echo "driver_exit=$?" >> "$S"
fi
# The counters write their record when the host ends, so it is stopped before the counts are read.
kill "$HOST_PID" > /dev/null 2>&1
wait "$HOST_PID" 2> /dev/null
echo "host_exit=$?" >> "$S"
python3 -B -m sesstrace witness counts --spec "$WITNESS" --cell "$CELL" --revision "$REVISION" --checkout "$CHECKOUT" \
  --raw "$RAW" --out "/out/counts/counts_${CELL}_${REVISION}.json" > "$L/counts.txt" 2>&1
echo "counts_exit=$?" >> "$S"
(cd "$CHECKOUT" && bash -c "$PKGLIST") > "/out/logs/packages_${CELL}_${REVISION}.txt" 2>&1 < /dev/null
finish
cat "$L/counts.txt"
