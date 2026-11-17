#!/usr/bin/env bash
# Put the attempts of one application series together and evaluate them as one.
#
# Usage:  bash checks/run/merge.sh <first|second|third> <new output folder> <output folder of an attempt>...
#
# An attempt made with ONLY_REVISION holds the runs of one release only, and an attempt in which the image of a release
# could not be fetched lacks that release. Each of them alone is evaluated with runs missing. This step copies the
# results of the attempts, unchanged, into one folder (a file that two attempts both hold stops it: nothing is run
# twice), and then runs the evaluation and the audit in the tool image, without network. No target is contacted.
# The freeze block "applications_<series>" must still match, so that the attempts are evaluated with the
# specification they were run with.
set -eu
. "$(dirname "$0")/common.sh"
[ $# -ge 4 ] || { echo "usage: bash checks/run/merge.sh <first|second|third> <new output folder> <output folder of an attempt>..." >&2; exit 2; }
SERIES="$1"
case "$SERIES" in
  first)  SPEC=phase3/SPEC_CELLS_D.json ;;
  second) SPEC=phase3b/SPEC_CELLS_3B.json ;;
  third)  SPEC=phase3c/SPEC_CELLS_3C.json ;;
  *) echo "the series is first, second or third" >&2; exit 2 ;;
esac
OUT="$(new_output "$2")"; shift 2
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
copy_repository "$WORK"
H="$OUT/environment_host.txt"
host_record "$H" "application cells ($SERIES), attempts put together: $*"
require_freeze "$WORK" "applications_$SERIES" "$OUT/freeze_check.txt"

RESULTS=""
for ATTEMPT in "$@"; do
  [ -d "$ATTEMPT/results" ] || { echo "no results folder in $ATTEMPT" | tee -a "$H" >&2; exit 2; }
  RESULTS="$RESULTS $(cd "$ATTEMPT/results" && pwd)"
done
# shellcheck disable=SC2086
(cd "$WORK/repo" && PYTHONPATH=src python3 -B -m sesstrace merge --out "$OUT" $RESULTS) > "$OUT/merge.stdout.txt" 2>&1 \
  || { cat "$OUT/merge.stdout.txt" >&2; echo "merge_exit=1" >> "$H"; exit 1; }
echo "merge_exit=0" >> "$H"

set +e
in_tool_image "$WORK" "$OUT" "python3 -B -m sesstrace evaluate --spec /tool/checks/$SPEC --results /out/results --out /out/evaluation.json > /out/evaluate.stdout.txt 2> /out/evaluate.stderr.txt; echo evaluate_exit=\$? >> /out/evaluate.stdout.txt; python3 -B -m sesstrace audit --spec /tool/checks/$SPEC --results /out/results --out /out/audit.json > /out/audit.stdout.txt 2>&1; echo audit_exit=\$? >> /out/audit.stdout.txt"
echo "evaluation_container_exit=$?" >> "$H"
set -e
echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$H"
cat "$OUT/merge.stdout.txt" "$OUT/evaluate.stdout.txt"
tail -n 2 "$OUT/audit.stdout.txt"
