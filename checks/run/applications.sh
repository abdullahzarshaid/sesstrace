#!/usr/bin/env bash
# The cells of the complete applications.
#
# Usage:  bash checks/run/applications.sh <first|second> <new output folder> <boot|run> <target>...
#   first    specification checks/phase3/SPEC_CELLS_D.json      (T5, T6, T7, T8)
#   second   specification checks/phase3b/SPEC_CELLS_3B.json    (T5.grant_withdrawn, second attempt of T7.credential_change)
#   boot     start each application once, run its set-up and ask the adapter for /ready; no checkpoint is sent
#   run      every cell of the named targets, the number of times the specification says
#
# For every run: a private network created with --internal (no route out), a secrets volume filled by a throw-away
# container without network, the application container from the image pinned by digest (no published port), and one
# container for the set-up, the adapter and the driver. Containers, network and volume are removed after the run, so
# every run starts from an empty application. ONLY_REVISION=vulnerable or fixed restricts the run to one release.
# The freeze block "applications_first" or "applications_second" must exist and match.
set -eu
. "$(dirname "$0")/common.sh"
[ $# -ge 4 ] || { echo "usage: bash checks/run/applications.sh <first|second> <new output folder> <boot|run> <target>..." >&2; exit 2; }
SERIES="$1"; MODE="$3"
case "$SERIES" in
  first)  SPEC=phase3/SPEC_CELLS_D.json;   SCRIPTS=/p3 ;;
  second) SPEC=phase3b/SPEC_CELLS_3B.json; SCRIPTS=/k ;;
  *) echo "the series is first or second" >&2; exit 2 ;;
esac
case "$MODE" in boot|run) ;; *) echo "the mode is boot or run" >&2; exit 2 ;; esac
OUT="$(new_output "$2")"; shift 3
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
copy_repository "$WORK"
H="$OUT/environment_host.txt"
host_record "$H" "application cells ($SERIES), mode $MODE, targets $*"
require_freeze "$WORK" "applications_$SERIES" "$OUT/freeze_check.txt"
MOUNTS="$(mounts "$WORK")"

"$ENGINE" pull "$TOOL_IMAGE" > "$OUT/container_pull_tool.txt" 2>&1
echo "tool image=$TOOL_IMAGE digest=$("$ENGINE" image inspect --format '{{json .RepoDigests}}' "$TOOL_IMAGE")" >> "$OUT/container_images.txt"
if [ "$MODE" = run ]; then
  set +e
  "$ENGINE" run --rm --network none --security-opt no-new-privileges -v "$WORK/repo":/tool:ro "$TOOL_IMAGE" \
    sh -c 'cd /tool && python3 -B -m unittest' > "$OUT/unit_tests.txt" 2>&1
  echo "unit_tests_exit=$?" >> "$H"
  set -e
fi

one_run() {  # target revision cell run-number mode
  local target="$1" revision="$2" cell="$3" number="$4" mode="$5"
  local id image options command
  id="sesstrace-$(echo "$target-$revision-$cell-$number" | tr 'A-Z._' 'a-z--')"
  image="$(plan "$WORK" image "$SPEC" "$target" "$revision")"
  options="$(plan "$WORK" app-options "$SPEC" "$target")"
  command="$(plan "$WORK" app-command "$SPEC" "$target")"
  "$ENGINE" network create --internal "$id" > /dev/null
  "$ENGINE" volume create "$id" > /dev/null
  "$ENGINE" run --rm --network none --security-opt no-new-privileges -v "$id":/secrets -v "$WORK/repo/checks/phase3":/p3:ro \
    "$TOOL_IMAGE" sh /p3/setup/make_secrets.sh > /dev/null 2>&1
  # The options and the command come from the specification, already quoted for the shell by plan.py.
  eval "\"\$ENGINE\" run -d --name \"\$id-app\" --network \"\$id\" --network-alias app --security-opt no-new-privileges -v \"\$id\":/secrets:ro $options \"\$image\" $command" > /dev/null
  # shellcheck disable=SC2086
  "$ENGINE" run --rm --network "$id" --security-opt no-new-privileges $MOUNTS -v "$id":/secrets:ro -v "$OUT":/out \
    "$TOOL_IMAGE" bash /tool/checks/run/in_container_applications.sh "/tool/checks/$SPEC" "$SCRIPTS" "applications_$SERIES" \
    "$target" "$revision" "$cell" "$number" "$mode" >> "$OUT/console_${target}_${revision}.txt" 2>&1 || true
  if [ "$number" = 1 ]; then "$ENGINE" logs "$id-app" 2>&1 | head -n 40 > "$OUT/app_log_head_${target}_${revision}_${cell}.txt"; fi
  "$ENGINE" rm -f "$id-app" > /dev/null 2>&1
  "$ENGINE" volume rm "$id" > /dev/null 2>&1
  "$ENGINE" network rm "$id" > /dev/null 2>&1
}

for TARGET in "$@"; do
  for REVISION in ${ONLY_REVISION:-vulnerable fixed}; do
    IMAGE="$(plan "$WORK" image "$SPEC" "$TARGET" "$REVISION")"
    "$ENGINE" pull "$IMAGE" > "$OUT/container_pull_${TARGET}_${REVISION}.txt" 2>&1 || { echo "Could not pull $IMAGE" | tee -a "$H"; continue; }
    DIGEST="$("$ENGINE" image inspect --format '{{index .RepoDigests 0}}' "$IMAGE")"
    echo "$TARGET $REVISION image=$IMAGE digest=$DIGEST" >> "$OUT/container_images.txt"
    # For an application the pinned revision is the image digest.
    { echo "head=${DIGEST##*@}"; echo "install_exit=0"; } > "$OUT/results/setup_${TARGET}_${REVISION}.txt"
    if [ "$MODE" = boot ]; then
      one_run "$TARGET" "$REVISION" BOOT 1 boot
    else
      for CELL in $(plan "$WORK" cells "$SPEC" "$TARGET"); do
        for NUMBER in $(seq 1 "$(plan "$WORK" repeats "$SPEC")"); do
          one_run "$TARGET" "$REVISION" "$CELL" "$NUMBER" run
        done
      done
    fi
  done
done

if [ "$MODE" = run ]; then
  set +e
  in_tool_image "$WORK" "$OUT" "python3 -B -m sesstrace evaluate --spec /tool/checks/$SPEC --results /out/results --out /out/evaluation.json > /out/evaluate.stdout.txt 2> /out/evaluate.stderr.txt; echo evaluate_exit=\$? >> /out/evaluate.stdout.txt; python3 -B -m sesstrace audit --spec /tool/checks/$SPEC --results /out/results --out /out/audit.json > /out/audit.stdout.txt 2>&1; echo audit_exit=\$? >> /out/audit.stdout.txt"
  echo "evaluation_container_exit=$?" >> "$H"
  set -e
  cat "$OUT/evaluate.stdout.txt"
  tail -n 2 "$OUT/audit.stdout.txt"
fi
echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$H"
