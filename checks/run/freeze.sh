#!/usr/bin/env bash
# Write the freeze block of one series into FREEZE_LOG.txt at the top of the repository.
#
# Usage:  bash checks/run/freeze.sh <libraries|witness|distributions|applications_first|applications_second|applications_third> "<reason>"
#
# The block lists the specification with its expected outcomes, the host applications, adapters and set-up scripts of
# the series, the runner scripts and every source file of the package. Write it before the first request of a series
# reaches a target, and commit it. A repair adds a new block with the same name; blocks are never edited.
set -eu
. "$(dirname "$0")/common.sh"
[ $# -eq 2 ] || { echo "usage: bash checks/run/freeze.sh <series> \"<reason>\"" >&2; exit 2; }
SERIES="$1"; REASON="$2"
cd "$REPO"

PACKAGE="$(find src/sesstrace -type f \( -name '*.py' -o -name '*.json' \) | LC_ALL=C sort)"
RUNNERS="$(find checks/run -type f | LC_ALL=C sort)"
LIBRARY_HOSTS="checks/external_targets/hosts/fastify_session_host.js checks/external_targets/hosts/fastify_secure_session_host.js checks/phase2/hosts/aiohttp_session_host.py checks/phase2/hosts/rack_session_host.rb"
case "$SERIES" in
  libraries)
    FILES="checks/phase3/SPEC_CELLS.json $LIBRARY_HOSTS" ;;
  witness)
    FILES="checks/phase3/SPEC_CELLS.json checks/phase3/SPEC_WITNESS.json $LIBRARY_HOSTS $(find checks/phase3/witness -type f | LC_ALL=C sort)" ;;
  applications_first)
    FILES="checks/phase3/SPEC_CELLS_D.json $(find checks/phase3/adapters checks/phase3/setup -type f | LC_ALL=C sort)" ;;
  applications_second)
    FILES="checks/phase3b/SPEC_CELLS_3B.json checks/phase3/setup/make_secrets.sh checks/phase3/adapters/directus_adapter.py $(find checks/phase3b/adapters checks/phase3b/setup -type f | LC_ALL=C sort)" ;;
  applications_third)
    FILES="checks/phase3c/SPEC_CELLS_3C.json checks/phase3/setup/make_secrets.sh checks/phase3b/adapters/vikunja_share_adapter.py checks/phase3b/setup/vikunja_share_setup.sh" ;;
  distributions)
    FILES="checks/phase3/MATRIX_PLAN.json $(find checks/phase3/A_dockerfiles -type f | LC_ALL=C sort)" ;;
  *) echo "unknown series: $SERIES" >&2; exit 2 ;;
esac
# shellcheck disable=SC2086
PYTHONPATH=src python3 -B -m sesstrace freeze write . "$SERIES" --reason "$REASON" $FILES $RUNNERS $PACKAGE
