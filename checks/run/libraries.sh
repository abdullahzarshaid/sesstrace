#!/usr/bin/env bash
# The cells of the four library targets (specification checks/phase3/SPEC_CELLS.json).
#
# Usage:  bash checks/run/libraries.sh <new output folder>
#
# One throw-away container per target and revision, removed afterwards. Inside it the library is cloned at the pinned
# commit and installed once; then every cell of the target is run the number of times the specification says, with the
# host application started fresh for each run. The unit tests of the package run once per image, without network,
# before any library is fetched. The evaluation and the audit run at the end, without network.
# The freeze block "libraries" must exist and match (bash checks/run/freeze.sh libraries).
set -eu
. "$(dirname "$0")/common.sh"
[ $# -eq 1 ] || { echo "usage: bash checks/run/libraries.sh <new output folder>" >&2; exit 2; }
SPEC=phase3/SPEC_CELLS.json
OUT="$(new_output "$1")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
copy_repository "$WORK"
H="$OUT/environment_host.txt"
host_record "$H" "library cells"
require_freeze "$WORK" libraries "$OUT/freeze_check.txt"
MOUNTS="$(mounts "$WORK")"

for IMG in $(plan "$WORK" images "$SPEC"); do
  NAME="$(echo "$IMG" | cut -d@ -f1 | tr '/:' '__')"
  "$ENGINE" pull "$IMG" > "$OUT/container_pull_$NAME.txt" 2>&1 || { echo "Could not pull $IMG" | tee -a "$H" >&2; exit 5; }
  echo "image=$IMG digest=$("$ENGINE" image inspect --format '{{json .RepoDigests}}' "$IMG")" >> "$OUT/container_images.txt"
  set +e
  "$ENGINE" run --rm --network none --security-opt no-new-privileges -v "$WORK/repo":/tool:ro "$IMG" \
    sh -c 'cd /tool && python3 -B -m unittest' > "$OUT/unit_tests_$NAME.txt" 2>&1
  echo "unit_tests_exit image=$IMG exit=$?" >> "$H"
  set -e
done

for TARGET in $(plan "$WORK" targets "$SPEC"); do
  for REVISION in vulnerable fixed; do
    set +e
    # shellcheck disable=SC2086
    "$ENGINE" run --rm --security-opt no-new-privileges $MOUNTS -v "$OUT":/out \
      "$(plan "$WORK" image "$SPEC" "$TARGET")" bash /tool/checks/run/in_container_libraries.sh "$TARGET" "$REVISION" \
      > "$OUT/container_${TARGET}_${REVISION}.txt" 2>&1
    echo "container_exit_${TARGET}_${REVISION}=$?" >> "$H"
    set -e
  done
done

set +e
in_tool_image "$WORK" "$OUT" "python3 -B -m sesstrace evaluate --spec /tool/checks/$SPEC --results /out/results --out /out/evaluation.json > /out/evaluate.stdout.txt 2> /out/evaluate.stderr.txt; echo evaluate_exit=\$? >> /out/evaluate.stdout.txt; python3 -B -m sesstrace audit --spec /tool/checks/$SPEC --results /out/results --out /out/audit.json > /out/audit.stdout.txt 2>&1; echo audit_exit=\$? >> /out/audit.stdout.txt"
echo "evaluation_container_exit=$?" >> "$H"
set -e
echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$H"
cat "$OUT/evaluate.stdout.txt"
tail -n 2 "$OUT/audit.stdout.txt"
