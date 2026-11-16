#!/usr/bin/env bash
# The synthetic laboratory and the unit tests of the package on the images of checks/phase3/MATRIX_PLAN.json.
#
# Usage:
#   bash checks/run/distributions.sh build <new folder for the build records>
#       pulls every image of the plan and builds the derived images (network: the registry and the distributions'
#       own package mirrors)
#   bash checks/run/distributions.sh run <new output folder>
#       runs every image once with --network none and the repository mounted read-only
#
# Only the list of images is taken from the plan (id, base image, Dockerfile, Python command). What is expected of
# every image is: the unit tests pass, and `sesstrace lab verify` reports the twelve trace files byte-identical to the
# reference and the expiration result equal. The freeze block "distributions" must exist and match for a run.
set -eu
. "$(dirname "$0")/common.sh"
[ $# -eq 2 ] || { echo "usage: bash checks/run/distributions.sh <build|run> <new output folder>" >&2; exit 2; }
MODE="$1"
PLAN=phase3/MATRIX_PLAN.json
tag_of() { echo "sesstrace-matrix/$(echo "$1" | tr 'A-Z' 'a-z'):local"; }
OUT="$(new_output "$2")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
copy_repository "$WORK"

if [ "$MODE" = build ]; then
  set +e
  echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUT/build_records.txt"
  plan "$WORK" matrix "$PLAN" | while read -r ID BASE DOCKERFILE PYTHON; do
    "$ENGINE" pull "$BASE" > "$OUT/pull_$ID.txt" 2>&1
    echo "$ID pull_exit=$?" >> "$OUT/build_records.txt"
    if [ "$DOCKERFILE" != "-" ]; then
      "$ENGINE" build --pull=false -t "$(tag_of "$ID")" -f "$WORK/repo/checks/phase3/$DOCKERFILE" "$WORK/repo/checks/phase3/A_dockerfiles" > "$OUT/build_$ID.txt" 2>&1
      echo "$ID build_exit=$?" >> "$OUT/build_records.txt"
    fi
  done
  echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/build_records.txt"
  cat "$OUT/build_records.txt"
  exit 0
fi
[ "$MODE" = run ] || { echo "the mode is build or run" >&2; exit 2; }

H="$OUT/environment_host.txt"
host_record "$H" "laboratory on several distributions"
require_freeze "$WORK" distributions "$OUT/freeze_check.txt"
mkdir -p "$OUT/runs"

plan "$WORK" matrix "$PLAN" | while read -r ID BASE DOCKERFILE PYTHON; do
  if [ "$DOCKERFILE" = "-" ]; then IMG="$BASE"; else IMG="$(tag_of "$ID")"; fi
  {
    echo "$ID base=$BASE base_digest=$("$ENGINE" image inspect --format '{{json .RepoDigests}}' "$BASE" 2>&1)"
    echo "$ID image_used=$IMG image_id=$("$ENGINE" image inspect --format '{{.Id}}' "$IMG" 2>&1)"
  } >> "$OUT/images.txt"
  set +e
  "$ENGINE" run --rm --network none --security-opt no-new-privileges -v "$WORK/repo":/tool:ro -v "$OUT/runs":/out \
    "$IMG" sh /tool/checks/run/in_container_distribution.sh "$ID" "$PYTHON" > "$OUT/runs/container_$ID.txt" 2>&1 < /dev/null
  echo "$ID container_exit=$?" >> "$H"
  set -e
done

python3 -I "$WORK/repo/checks/run/matrix_table.py" "$OUT" | tee "$OUT/matrix_table.txt"
echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$H"
