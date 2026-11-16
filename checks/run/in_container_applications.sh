#!/usr/bin/env bash
# Runs in the container of the set-up, the adapter and the driver, on the private network of one run; the application
# is reachable as "app". Started by applications.sh.
# Usage: bash /tool/checks/run/in_container_applications.sh <specification> <folder of the set-up and adapter paths>
#            <freeze block> <target> <vulnerable|fixed> <cell or BOOT> <run number> <boot|run>
#   boot  wait for the application, run the set-up, start the adapter and ask it for /ready; nothing else
#   run   as boot, then the driver sends the plan of the cell
# Mounts: /tool, /p3, /k read-only; /secrets read-only; /out writable.
set -u
SPEC="$1"; SCRIPTS="$2"; BLOCK="$3"; TARGET="$4"; REVISION="$5"; CELL="$6"; NUMBER="$7"; MODE="$8"
PORT=18400
export PYTHONPATH=/tool/src
RUN=$(printf "run_%02d" "$NUMBER")
TAG="${TARGET}_${REVISION}_${CELL}_${RUN}"
mkdir -p /out/results /out/logs /out/records
E=/out/records/environment_$TAG.txt
{
  echo "target=$TARGET revision=$REVISION cell=$CELL run=$NUMBER mode=$MODE"
  echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "python=$(python3 --version 2>&1)"
  echo "sesstrace=$(python3 -B -m sesstrace --version 2>&1)"
} > "$E"
finish() { echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$E"; chmod -R a+rX /out; }

(cd /tool && python3 -B -m sesstrace freeze check . "$BLOCK") > "/out/records/freeze_check_$TAG.txt" 2>&1
FROZEN=$?
echo "freeze_check_exit=$FROZEN" >> "$E"
if [ "$FROZEN" != 0 ]; then echo "freeze_check=failed, nothing was run" >> "$E"; finish; exit 5; fi

eval "$(python3 /tool/checks/run/plan.py application "$SPEC" "$TARGET")"

APP_UP=0
for _ in $(seq 1 300); do
  if curl -s -o /dev/null -w '%{http_code}' -m 3 "http://app:$APPPORT$READY" 2>/dev/null | grep -q '^200$'; then APP_UP=1; break; fi
  sleep 1
done
echo "app_ready=$APP_UP" >> "$E"

SETUP_EXIT=9
if [ "$APP_UP" = 1 ]; then
  sh "$SCRIPTS/$SETUP" > "/out/logs/setup_$TAG.txt" 2>&1
  SETUP_EXIT=$?
fi
echo "setup_exit=$SETUP_EXIT" >> "$E"
grep '^version=' "/out/logs/setup_$TAG.txt" 2>/dev/null | head -n 1 | sed 's/^version=/app_reported_version=/' >> "$E"

ADAPTER_UP=0
if [ "$SETUP_EXIT" = 0 ]; then
  python3 "$SCRIPTS/$ADAPTER" "$PORT" "/out/logs/adapter_requests_$TAG.txt" > "/out/logs/adapter_$TAG.txt" 2>&1 &
  ADAPTER_PID=$!
  for _ in $(seq 1 60); do
    if curl -s -f -m 3 "http://127.0.0.1:$PORT/ready" > /dev/null 2>&1; then ADAPTER_UP=1; break; fi
    sleep 0.5
  done
fi
echo "adapter_ready=$ADAPTER_UP" >> "$E"

if [ "$MODE" = run ]; then
  echo "${RUN}_${CELL}_host_ready=$ADAPTER_UP" >> "/out/results/setup_${TARGET}_${REVISION}.txt"
  if [ "$ADAPTER_UP" = 1 ]; then
    R=/out/results/$CELL/$REVISION/$RUN
    mkdir -p "$R"
    python3 -B -m sesstrace run --spec "$SPEC" --entry "$CELL" --revision "$REVISION" --base "http://127.0.0.1:$PORT" \
      --out "$R" > "/out/logs/driver_$TAG.txt" 2>&1 < /dev/null
    echo "driver_exit=$?" >> "$E"
  fi
else
  echo "boot_ready=$ADAPTER_UP" >> "$E"
fi
if [ -n "${ADAPTER_PID:-}" ]; then kill "$ADAPTER_PID" > /dev/null 2>&1; wait "$ADAPTER_PID" 2> /dev/null; fi
finish
grep -E "app_ready|setup_exit|adapter_ready|driver_exit|app_reported_version" "$E" | tr '\n' ' '
echo
