#!/usr/bin/env bash
# Shared by the runners in this folder. Source it; do not run it.
#
# Every runner works on a private copy of the repository, so that nothing a container can reach is the working tree, and
# mounts that copy read-only:
#   /tool   the repository (the package is run from /tool/src)
#   /ext    checks/external_targets     /p2   checks/phase2
#   /p3     checks/phase3               /k    checks
# The last four are the paths the frozen specifications use for their host applications, adapters and set-up scripts.
# Containers get no --privileged, no host network and no published port.

ENGINE="${CONTAINER_ENGINE:-docker}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The image the set-up, the adapters, the driver and the evaluator run in (Python 3.7 on Debian 12, pinned by digest).
TOOL_IMAGE="docker.io/library/python@sha256:eedf63967cdb57d8214db38ce21f105003ed4e4d0358f02bedc057341bcf92a0"

# new_output <folder>: refuse to reuse a folder, create it, print its absolute path
new_output() {
  if [ -e "$1" ]; then echo "Refusing to reuse an existing output folder: $1" >&2; exit 4; fi
  mkdir -p "$1"
  (cd "$1" && pwd)
}

# fetch_image <image pinned by digest> <record file>: pull the image; when the registry cannot be reached and an image
# with this digest is already on the machine, use that one. The record file says which of the two happened.
fetch_image() {
  if "$ENGINE" pull "$1" > "$2" 2>&1; then return 0; fi
  case "$1" in *@sha256:*) ;; *) return 1 ;; esac
  if "$ENGINE" image inspect "$1" > /dev/null 2>&1; then
    echo "pull failed; the image with this digest is already on this machine and is used" >> "$2"
    return 0
  fi
  return 1
}

# copy_repository <work folder>: copy what the containers need, without the version history
copy_repository() {
  mkdir -p "$1/repo"
  (cd "$REPO" && tar -cf - --exclude=.git --exclude=__pycache__ .) | (cd "$1/repo" && tar -xf -)
}

# mounts <work folder>: the read-only mounts every container gets
mounts() {
  echo "-v $1/repo:/tool:ro -v $1/repo/checks/external_targets:/ext:ro -v $1/repo/checks/phase2:/p2:ro -v $1/repo/checks/phase3:/p3:ro -v $1/repo/checks:/k:ro"
}

# host_record <file> <series>: what the host is
host_record() {
  {
    echo "series=$2"
    echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel=$(uname -a)"
    [ -r /etc/os-release ] && . /etc/os-release && echo "distribution=$PRETTY_NAME (VERSION=${VERSION:-})"
    echo "container_engine=$ENGINE client $("$ENGINE" version --format '{{.Client.Version}}' 2>&1) server $("$ENGINE" version --format '{{.Server.Version}}' 2>&1)"
    echo "repository_commit=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "repository_clean=$([ -z "$(git -C "$REPO" status --porcelain 2>/dev/null)" ] && echo yes || echo no)"
  } > "$1"
}

# plan <work folder> <command> <specification, relative to checks/> [<argument>...]: see plan.py
plan() {
  local work="$1" command="$2" spec="$3"; shift 3
  python3 -I "$work/repo/checks/run/plan.py" "$command" "$work/repo/checks/$spec" "$@"
}

# require_freeze <work folder> <block> <output file>: stop unless the files of the block are unchanged
require_freeze() {
  if ! (cd "$1/repo" && PYTHONPATH=src python3 -B -m sesstrace freeze check . "$2") > "$3" 2>&1; then
    echo "freeze check of block $2 failed; nothing was run (see $3)" >&2
    exit 5
  fi
}

# in_tool_image <work folder> <output folder> <shell command>: run a command of the package without network
in_tool_image() {
  "$ENGINE" run --rm --network none --security-opt no-new-privileges -e PYTHONPATH=/tool/src \
    -v "$1/repo":/tool:ro -v "$2":/out "$TOOL_IMAGE" sh -c "cd /tmp && $3; chmod -R a+rX /out"
}
