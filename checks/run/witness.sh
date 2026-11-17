#!/usr/bin/env bash
# The line witness of the library cells named in checks/phase3/SPEC_WITNESS.json.
#
# Usage:  bash checks/run/witness.sh <new output folder>
#
# One throw-away container per cell and revision. The cell is run once more with the line counter of the language
# switched on from outside the host application, whose file stays unchanged. The evaluation and the audit of the
# witness runs run at the end, without network. The freeze block "witness" must exist and match
# (bash checks/run/freeze.sh witness).
set -eu
. "$(dirname "$0")/common.sh"
[ $# -eq 1 ] || { echo "usage: bash checks/run/witness.sh <new output folder>" >&2; exit 2; }
SPEC=phase3/SPEC_CELLS.json
WITNESS=phase3/SPEC_WITNESS.json
OUT="$(new_output "$1")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
copy_repository "$WORK"
H="$OUT/environment_host.txt"
host_record "$H" "line witness"
require_freeze "$WORK" witness "$OUT/freeze_check.txt"
mkdir -p "$OUT/results"
MOUNTS="$(mounts "$WORK")"

for CELL in $(plan "$WORK" witness-cells "$WITNESS"); do
  TARGET="${CELL%%.*}"
  IMG="$(plan "$WORK" image "$SPEC" "$TARGET")"
  fetch_image "$IMG" "$OUT/container_pull_$TARGET.txt" || { echo "Could not pull $IMG" | tee -a "$H" >&2; exit 5; }
  grep -q "image=$IMG " "$OUT/container_images.txt" 2>/dev/null \
    || echo "image=$IMG digest=$("$ENGINE" image inspect --format '{{json .RepoDigests}}' "$IMG")" >> "$OUT/container_images.txt"
  for REVISION in vulnerable fixed; do
    set +e
    # shellcheck disable=SC2086
    "$ENGINE" run --rm --security-opt no-new-privileges $MOUNTS -v "$OUT":/out \
      "$IMG" bash /tool/checks/run/in_container_witness.sh "$CELL" "$REVISION" > "$OUT/container_${CELL}_${REVISION}.txt" 2>&1
    echo "container_exit_${CELL}_${REVISION}=$?" >> "$H"
    set -e
  done
done

set +e
in_tool_image "$WORK" "$OUT" "python3 -B -m sesstrace witness evaluate --cells /tool/checks/$SPEC --spec /tool/checks/$WITNESS --results /out --out /out/witness_evaluation.json > /out/evaluate.stdout.txt 2> /out/evaluate.stderr.txt; echo evaluate_exit=\$? >> /out/evaluate.stdout.txt; python3 -B -m sesstrace witness audit --cells /tool/checks/$SPEC --spec /tool/checks/$WITNESS --results /out --out /out/audit.json > /out/audit.stdout.txt 2>&1; echo audit_exit=\$? >> /out/audit.stdout.txt"
echo "evaluation_container_exit=$?" >> "$H"
set -e
echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$H"
cat "$OUT/evaluate.stdout.txt"
tail -n 2 "$OUT/audit.stdout.txt"
