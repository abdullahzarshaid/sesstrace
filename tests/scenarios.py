"""Run the entries of a specification against stub servers, the way a real check runs them.

The helpers write the same files a container run writes (set-up records,
summaries, traces) into a temporary folder and return the evaluation.
"""
import copy
import tempfile
from pathlib import Path

from sesstrace.fileio import read_json, write_text
from sesstrace.replay import audit, driver, evaluate, spec as specification

CHECKS = Path(__file__).resolve().parents[1] / "checks"
# The folders keep the names of the archive, because the specifications name their files by these paths.
SPEC_FILES = {
    "EXTERNAL_SPEC.json": CHECKS / "external_targets" / "EXTERNAL_SPEC.json",
    "EXTERNAL_SPEC_PHASE2.json": CHECKS / "phase2" / "EXTERNAL_SPEC_PHASE2.json",
    "SPEC_CELLS.json": CHECKS / "phase3" / "SPEC_CELLS.json",
    "SPEC_CELLS_D.json": CHECKS / "phase3" / "SPEC_CELLS_D.json",
    "SPEC_WITNESS.json": CHECKS / "phase3" / "SPEC_WITNESS.json",
    "SPEC_CELLS_3B.json": CHECKS / "phase3b" / "SPEC_CELLS_3B.json",
}


def load(name):
    return specification.load(SPEC_FILES[name])


def shortened(spec, only=None, repeats=None):
    """A copy of a specification with short waits, so that a test takes seconds."""
    spec = copy.deepcopy(spec)
    if only:
        spec["targets"] = [entry for entry in spec["targets"] if entry["id"] in only]
    if repeats is not None:
        spec["repeats_per_revision"] = repeats
    for entry in spec["targets"]:
        if "lifetime_seconds" in entry:
            entry["lifetime_seconds"] = 0.5
        if "boundary_wait_seconds" in entry:
            entry["boundary_wait_seconds"] = 1.0
        if "slow_seconds" in entry:
            entry["slow_seconds"] = 0.9
        if "head_start_seconds" in entry:
            entry["head_start_seconds"] = 0.25
    return spec


def run_targets(spec, make_stub, wrong_head=None):
    """One run per entry and revision. `make_stub(entry, variant)` returns a started stub.

    Returns (evaluation rows by id, summaries by file stem, audit report).
    """
    with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
        results = Path(scratch)
        for entry in spec["targets"]:
            for variant in specification.VARIANTS:
                head = "0" * 40 if wrong_head == (entry["id"], variant) else entry[variant + "_commit"]
                write_text(results / ("setup_%s_%s.txt" % (entry["id"], variant)),
                           "head=%s\ninstall_exit=0\nhost_ready=1\n" % head)
                with make_stub(entry, variant) as stub:
                    driver.run_entry(spec, entry["id"], variant, stub.base_url, results)
        report = evaluate.evaluate(spec, results)
        summaries = {path.stem: read_json(path) for path in results.glob("summary_*.json")}
        return {row["id"]: row for row in report["targets"]}, summaries, audit.audit_results(spec, results)


def run_cells(spec, make_stub, not_ready=()):
    """`repeats_per_revision` runs per cell and revision. `make_stub(entry, variant, run)` returns a started stub.

    `not_ready` holds (cell, variant, run) triples whose target never came up.
    Returns (evaluation rows by cell, whole evaluation, audit report).
    """
    with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
        results = Path(scratch)
        setup = {}
        for entry in spec["targets"]:
            for variant in specification.VARIANTS:
                lines = setup.setdefault((entry["target"], variant), ["head=" + entry[variant + "_commit"], "install_exit=0"])
                for number in range(1, int(spec["repeats_per_revision"]) + 1):
                    label = "run_%02d" % number
                    if (entry["id"], variant, number) in not_ready:
                        lines.append("%s_%s_host_ready=0" % (label, entry["id"]))
                        continue
                    lines.append("%s_%s_host_ready=1" % (label, entry["id"]))
                    with make_stub(entry, variant, number) as stub:
                        driver.run_entry(spec, entry["id"], variant, stub.base_url, results / entry["id"] / variant / label)
        for (target, variant), lines in setup.items():
            write_text(results / ("setup_%s_%s.txt" % (target, variant)), "\n".join(lines) + "\n")
        report = evaluate.evaluate(spec, results)
        return {row["cell"]: row for row in report["cells"]}, report, audit.audit_results(spec, results)
