#!/usr/bin/env python3
"""Read what every image of the distribution matrix wrote and print one row per image.

Usage: python3 matrix_table.py <output folder of distributions.sh run>

Reads <out>/runs/<id>/environment.txt, unit_tests.txt and lab_verify.txt, prints the table and writes
<out>/matrix_result.json. An image is IDENTICAL when the unit tests passed and the laboratory reproduced the reference
output; DIFFERENT when both commands ran and one of them did not hold; FAILED when there is nothing to compare.
Standard library only.
"""
import json
import re
import sys
from pathlib import Path

WORDS = ("IDENTICAL", "DIFFERENT", "FAILED")


def key_values(path):
    pairs = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                pairs[key.strip()] = value.strip().strip('"')
    return pairs


def text_of(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def row_for(folder):
    environment = key_values(folder / "environment.txt")
    row = {"id": folder.name, "distribution": environment.get("PRETTY_NAME"), "version_id": environment.get("VERSION_ID"),
           "c_library": environment.get("libc_python"), "python_version": environment.get("python_version")}
    if not environment:
        row.update(result="FAILED", reasons=["no environment record: the container did not start or did not run the script"])
        return row
    tests = text_of(folder / "unit_tests.txt")
    ran = re.findall(r"^Ran (\d+) tests? in", tests, re.M)
    verify = text_of(folder / "lab_verify.txt")
    traces = re.search(r"trace files equal to the reference: (\d+) of (\d+)", verify)
    row["tests_run"] = int(ran[-1]) if ran else None
    row["tests_ok"] = bool(ran) and environment.get("unit_tests_exit") == "0"
    row["traces_identical"] = "%s of %s" % traces.groups() if traces else None
    row["laboratory_identical"] = "RESULT: identical" in verify and environment.get("lab_verify_exit") == "0"
    reasons = []
    if not ran or traces is None:
        row.update(result="FAILED", reasons=["no output to compare"])
        return row
    if not row["tests_ok"]:
        reasons.append("unit tests: exit %s" % environment.get("unit_tests_exit"))
    if not row["laboratory_identical"]:
        reasons.append("laboratory: %s trace files identical, exit %s" % (row["traces_identical"], environment.get("lab_verify_exit")))
    row.update(result="DIFFERENT" if reasons else "IDENTICAL", reasons=reasons)
    return row


def table(out_dir):
    runs = Path(out_dir) / "runs"
    rows = [row_for(folder) for folder in sorted(runs.iterdir()) if folder.is_dir()]
    return {"entries": rows, "counts": {word: sum(1 for row in rows if row["result"] == word) for word in WORDS},
            "distinct_distributions": len({row["distribution"] for row in rows if row["distribution"]})}


def main(argv):
    if len(argv) != 1:
        sys.exit(__doc__)
    result = table(argv[0])
    with open(str(Path(argv[0]) / "matrix_result.json"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(result, indent=2) + "\n")
    for row in result["entries"]:
        print("%-22s %-10s %-34s %-16s tests %-4s traces %-9s %s" % (
            row["id"], row["result"], row["distribution"], row["python_version"], row.get("tests_run"),
            row.get("traces_identical"), "; ".join(row["reasons"])))
    print("%d images, %d distinct distributions: %s" % (
        len(result["entries"]), result["distinct_distributions"],
        ", ".join("%s %d" % (word, result["counts"][word]) for word in WORDS)))


if __name__ == "__main__":
    main(sys.argv[1:])
