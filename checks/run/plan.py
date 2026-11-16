#!/usr/bin/env python3
"""Read what a runner needs from a specification and print it for the shell.

    plan.py images <cells spec>                      the library images, one per line
    plan.py image <spec> <target> [<revision>]       the image of a target (applications have one per revision)
    plan.py targets <spec>                           the targets that have cells, in file order
    plan.py cells <spec> <target>                    the cells of a target, in file order
    plan.py repeats <spec>                           runs per cell and revision
    plan.py library <spec> <target> <revision>       shell assignments for the checkout and installation of a library
    plan.py library-runs <spec> <target> <revision>  one line per run: <run number> <cell> <port> <host command>
    plan.py witness <spec> <target> <revision>       shell assignments for one witness run of a library
    plan.py witness-cells <witness spec>             the cells of the witness specification
    plan.py application <spec> <target>              shell assignments for an application: port, ready path, set-up, adapter
    plan.py app-options <spec> <target>              the -e options of the application container
    plan.py app-command <spec> <target>              the command of the application container, or nothing
    plan.py matrix <matrix plan>                     one line per image: <id> <base image> <Dockerfile or -> <python command>

Values that go into shell assignments are quoted with shlex. Standard library only.
"""
import json
import shlex
import sys

CHECKOUT = "/tmp/checkout/%s/%s"


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def cells_of(spec, target):
    return [entry["id"] for entry in spec["targets"] if entry["target"] == target]


def assignments(pairs):
    return "\n".join("%s=%s" % (name, shlex.quote(str(value))) for name, value in pairs)


def library(spec, target, revision):
    setup = spec["target_setup"][target]
    return assignments([("REPO", setup["repository"]), ("COMMIT", setup[revision + "_commit"]),
                        ("FETCH_BY_HASH", 1 if setup.get("fetch_by_hash") else 0),
                        ("INSTALL", setup["install_command"]), ("PKGLIST", setup["package_list_command"])])


def host_command(setup, target, revision, port):
    return setup["host_command"].format(checkout=CHECKOUT % (target, revision), port=port, **setup["host_values"])


def library_runs(spec, target, revision):
    """A fresh port for every run: port_base + 10 x run number + position of the cell within the target."""
    setup = spec["target_setup"][target]
    lines = []
    for run in range(1, int(spec["repeats_per_revision"]) + 1):
        for position, cell in enumerate(cells_of(spec, target)):
            port = setup["port_base"] + 10 * run + position
            lines.append("%02d %s %d %s" % (run, cell, port, host_command(setup, target, revision, port)))
    return "\n".join(lines)


def witness(spec, target, revision):
    setup = spec["target_setup"][target]
    port = setup["port_base"] + 500
    return library(spec, target, revision) + "\n" + assignments([("PORT", port), ("HOSTCMD", host_command(setup, target, revision, port))])


def application(spec, target):
    setup = spec["target_setup"][target]
    return assignments([("APPPORT", setup["app_port"]), ("READY", setup["app_ready_path"]),
                        ("SETUP", setup["setup_script"]), ("ADAPTER", setup["adapter"])])


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    command, spec, rest = argv[0], load(argv[1]), argv[2:]
    if command == "images":
        print("\n".join(sorted({setup["image"] for setup in spec["target_setup"].values()})))
    elif command == "image":
        image = spec["target_setup"][rest[0]]["image"]
        print(image[rest[1]] if isinstance(image, dict) else image)
    elif command == "targets":
        seen = []
        for entry in spec["targets"]:
            if entry["target"] not in seen:
                seen.append(entry["target"])
        print(" ".join(seen))
    elif command == "cells":
        print(" ".join(cells_of(spec, rest[0])))
    elif command == "repeats":
        print(int(spec["repeats_per_revision"]))
    elif command == "library":
        print(library(spec, rest[0], rest[1]))
    elif command == "library-runs":
        print(library_runs(spec, rest[0], rest[1]))
    elif command == "witness":
        print(witness(spec, rest[0], rest[1]))
    elif command == "witness-cells":
        print(" ".join(cell["cell"] for cell in spec["cells"]))
    elif command == "application":
        print(application(spec, rest[0]))
    elif command == "app-options":
        environment = spec["target_setup"][rest[0]]["app_env"]
        print(" ".join("-e " + shlex.quote("%s=%s" % pair) for pair in environment.items()))
    elif command == "app-command":
        words = spec["target_setup"][rest[0]]["app_command"]
        print(" ".join(shlex.quote(word) for word in words) if words else "")
    elif command == "matrix":
        for entry in spec["entries"]:
            print(entry["id"], entry["base_image"], entry["dockerfile"] or "-", entry["python_command"])
    else:
        sys.exit("unknown command: " + command)


if __name__ == "__main__":
    main(sys.argv[1:])
