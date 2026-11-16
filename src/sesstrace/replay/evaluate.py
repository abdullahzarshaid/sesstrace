"""Turn the records of finished runs into verdicts.

The evaluator reads files and nothing else: the specification, the set-up
record of every container and the summary the driver wrote for every run.
It compares what was observed with what the specification expected and never
changes either.

Two layouts are understood.

targets   one run per entry and revision
              <results>/setup_<id>_<revision>.txt
              <results>/summary_<id>_<revision>.json

cells     `repeats_per_revision` runs per entry and revision
              <results>/setup_<target>_<revision>.txt
              <results>/<cell>/<revision>/run_<NN>/summary_<cell>_<revision>.json

A run is valid when the set-up record shows the pinned revision and a clean
installation, the target was ready, every control checkpoint came out as
expected, no request failed in transport or order, and every wait or pause
lasted at least as long as required.

Verdict of an entry
    CONFIRMED       every run is valid and every replay came out as expected
    NOT_CONFIRMED   at least one valid run has a replay that differs
    INCONCLUSIVE    anything else (some run is not valid, none differs)
"""
from pathlib import Path

from ..fileio import read_json, read_key_values
from .spec import VARIANTS

VERDICTS = ("CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE")


def setup_problems(record, pinned, need_host_ready=True):
    """What the set-up record of one container says is wrong; an empty list means it is fine."""
    problems = []
    if record.get("head") != pinned:
        problems.append("checkout is not at the pinned commit")
    if record.get("install_exit") != "0":
        problems.append("installation did not exit with 0")
    if need_host_ready and record.get("host_ready") != "1":
        problems.append("host application did not become ready")
    return problems


def judge_summary(entry, summary, variant):
    """Check one summary against its entry.

    Returns (problems, observed). `problems` lists what makes the run invalid;
    `observed` maps every checkpoint that has an expectation to its outcome.
    A replay that differs from the expectation is not a problem here; the
    caller counts it.
    """
    kinds = [step["do"] for step in entry["plan"]]
    expected = entry["expected"][variant]
    observed = {name: summary["checkpoints"].get(name, {}).get("outcome") for name in expected}
    problems = []
    if summary.get("errors"):
        problems.append("%d step(s) with an error" % len(summary["errors"]))
    if summary.get("commit_expected") != entry[variant + "_commit"]:
        problems.append("summary belongs to another commit")
    for key, step_kind, label in (("waits", "wait_since", "wait"), ("pauses", "pause", "pause")):
        if step_kind not in kinds:
            continue
        recorded = summary.get(key, [])
        for item in recorded:
            if item.get("measured_seconds") is None or item["measured_seconds"] < item["required_seconds"]:
                problems.append("the %s was shorter than required" % label)
        if len(recorded) != kinds.count(step_kind):
            problems.append("not every %s was recorded" % label)
    orders = summary.get("concurrency", [])
    for order in orders:
        if order.get("order_ok") is not True:
            problems.append("background request %s did not span %s"
                            % (order.get("background_checkpoint"), order.get("spans_checkpoint")))
    spanning_joins = sum(1 for step in entry["plan"] if step["do"] == "join" and step.get("spans_checkpoint"))
    if "join" in kinds and len(orders) != spanning_joins:
        problems.append("not every background order was recorded")
    for name in entry["control_checkpoints"]:
        if observed.get(name) != expected[name]:
            problems.append("control %s was %s, expected %s" % (name, observed.get(name), expected[name]))
    return problems, observed


def evaluate_targets(spec, results_dir):
    """One run per entry and revision."""
    results_dir = Path(results_dir)
    report = {"specification": None, "targets": []}
    for entry in spec["targets"]:
        row = {"id": entry["id"], "cve": entry["cve"], "package": entry["package"], "revisions": {}, "reasons": []}
        inconclusive = False
        mismatch = False
        for variant in VARIANTS:
            setup_path = results_dir / ("setup_%s_%s.txt" % (entry["id"], variant))
            if setup_path.is_file():
                why = setup_problems(read_key_values(setup_path), entry[variant + "_commit"])
            else:
                why = ["no set-up record"]
            summary_path = results_dir / ("summary_%s_%s.json" % (entry["id"], variant))
            if why or not summary_path.is_file():
                inconclusive = True
                row["reasons"] += ["%s: %s" % (variant, text) for text in (why or ["no summary written"])]
                row["revisions"][variant] = {"observed": None}
                continue
            summary = read_json(summary_path)
            problems, observed = judge_summary(entry, summary, variant)
            expected = entry["expected"][variant]
            revision = {"expected": expected, "observed": observed,
                        "sesstrace_invariant": summary.get("sesstrace_invariant"),
                        "waits": summary.get("waits"), "http_steps": summary.get("http_steps")}
            for optional in ("pauses", "concurrency"):
                if optional in summary:
                    revision[optional] = summary[optional]
            row["revisions"][variant] = revision
            if problems:
                inconclusive = True
                row["reasons"] += ["%s: %s" % (variant, text) for text in problems]
            for name in entry["replay_checkpoints"]:
                if observed.get(name) != expected[name]:
                    mismatch = True
                    row["reasons"].append("%s: replay %s was %s, expected %s" % (variant, name, observed.get(name), expected[name]))
        row["verdict"] = "INCONCLUSIVE" if inconclusive else "NOT_CONFIRMED" if mismatch else "CONFIRMED"
        report["targets"].append(row)
    report["reading"] = spec["scope"]
    return report


def category(vulnerable, fixed):
    """Name the pattern of the replay outcomes of the valid runs of the two revisions."""
    if not vulnerable or not fixed:
        return "NO_VALID_RUN"
    before, after = set(vulnerable), set(fixed)
    if before == {"success"} and after == {"denied"}:
        return "FLIPS"
    if before == {"denied"} and after == {"denied"}:
        return "REFUSED_AT_BOTH"
    if before == {"success"} and after == {"success"}:
        return "ACCEPTED_AT_BOTH"
    return "MIXED"


def _cell_revision(entry, variant, replay_checkpoint, repeats, results_dir, reasons):
    """Judge every run of one cell at one revision. Returns (revision row, replays of valid runs, any invalid, any differing)."""
    setup = read_key_values(results_dir / ("setup_%s_%s.txt" % (entry["target"], variant)))
    setup_bad = setup_problems(setup, entry[variant + "_commit"], need_host_ready=False)
    wanted = entry["expected"][variant][replay_checkpoint]
    runs = []
    any_invalid = False
    any_differs = False
    for number in range(1, repeats + 1):
        key = "run_%02d" % number
        problems = list(setup_bad)
        if setup.get("%s_%s_host_ready" % (key, entry["id"])) != "1":
            problems.append("host application did not become ready")
        replay = None
        summary_path = results_dir / entry["id"] / variant / key / ("summary_%s_%s.json" % (entry["id"], variant))
        if not summary_path.is_file():
            problems.append("no summary written")
        else:
            found, observed = judge_summary(entry, read_json(summary_path), variant)
            problems += found
            replay = observed.get(replay_checkpoint)
        valid = not problems
        runs.append({"run": number, "valid": valid, "replay": replay,
                     "replay_as_expected": replay == wanted, "problems": problems})
        if not valid:
            any_invalid = True
            reasons.append("%s %s: invalid: %s" % (variant, key, "; ".join(problems)))
        if valid and replay != wanted:
            any_differs = True
            reasons.append("%s %s: replay %s was %s, expected %s" % (variant, key, replay_checkpoint, replay, wanted))
    valid_replays = [run["replay"] for run in runs if run["valid"]]
    counts = {}
    for word in ("success", "denied", "other", None):
        if valid_replays.count(word):
            counts["missing" if word is None else word] = valid_replays.count(word)
    note = "" if len(valid_replays) == repeats else " (%d of %d runs valid)" % (len(valid_replays), repeats)
    revision = {
        "runs": repeats, "valid_runs": len(valid_replays), "valid_replay_counts": counts,
        "count_text": "%s %d of %d accepted, %d of %d refused%s"
                      % (variant, valid_replays.count("success"), repeats, valid_replays.count("denied"), repeats, note),
        "all_runs": runs,
    }
    return revision, valid_replays, any_invalid, any_differs


def _reading(spec, rows):
    """Per target: which contracts change between the revisions, and whether that agrees with the frozen class."""
    reading = []
    for target in sorted({row["target"] for row in rows}):
        mine = [row for row in rows if row["target"] == target]
        flips = [row for row in mine if row["observed_category"] == "FLIPS"]
        conditions = sorted({spec["contract_lifecycle_condition"].get(row["contract"]) for row in flips})
        frozen = mine[0]["frozen_v2_class"]
        reading.append({"target": target, "package": mine[0]["package"], "frozen_v2_class": frozen,
                        "contracts_whose_outcome_changes": [row["contract"] for row in flips],
                        "lifecycle_condition_of_those_contracts": conditions,
                        "agrees_with_frozen_class": (conditions == [frozen]) if flips else None})
    return reading


def evaluate_cells(spec, results_dir):
    """Several runs per cell and revision."""
    results_dir = Path(results_dir)
    repeats = int(spec["repeats_per_revision"])
    rows = []
    for entry in spec["targets"]:
        replay_checkpoint = entry["replay_checkpoints"][0]
        row = {"cell": entry["id"], "target": entry["target"], "contract": entry["contract"], "cve": entry["cve"],
               "package": entry["package"], "frozen_v2_class": entry.get("frozen_v2_class"),
               "expected_category": entry["expected_category"], "replay_checkpoint": replay_checkpoint,
               "expected_replay": {variant: entry["expected"][variant][replay_checkpoint] for variant in VARIANTS},
               "revisions": {}, "reasons": []}
        valid_replays = {}
        any_invalid = False
        any_differs = False
        for variant in VARIANTS:
            revision, replays, invalid, differs = _cell_revision(entry, variant, replay_checkpoint, repeats,
                                                                 results_dir, row["reasons"])
            row["revisions"][variant] = revision
            valid_replays[variant] = replays
            any_invalid = any_invalid or invalid
            any_differs = any_differs or differs
        row["observed_category"] = category(valid_replays["vulnerable"], valid_replays["fixed"])
        row["count_text"] = ", ".join(row["revisions"][variant]["count_text"] for variant in VARIANTS)
        row["verdict"] = "NOT_CONFIRMED" if any_differs else "INCONCLUSIVE" if any_invalid else "CONFIRMED"
        rows.append(row)
    return {"specification": None, "repeats_per_revision": repeats, "reading_rule": spec.get("reading_rule"),
            "cells": rows, "reading": _reading(spec, rows),
            "counts": {word: sum(1 for row in rows if row["verdict"] == word) for word in VERDICTS},
            "scope": spec["scope"]}


def combine(reports):
    """Put the cells of several evaluations into one table.

    The reports are given in the order their series were run. A cell that was
    attempted again in a later series is taken from the later one and keeps
    its place in the table.
    """
    order = []
    latest = {}
    for report in reports:
        for row in report["cells"]:
            if row["cell"] not in latest:
                order.append(row["cell"])
            latest[row["cell"]] = row
    return [latest[name] for name in order]


def _verdicts(report):
    """{entry: (verdict, observed category or None)} for either layout."""
    if "cells" in report:
        return {row["cell"]: (row["verdict"], row["observed_category"]) for row in report["cells"]}
    return {row["id"]: (row["verdict"], None) for row in report["targets"]}


def compare(reference, fresh):
    """Compare a fresh evaluation with a reference one, entry by entry.

    Two runs of the same check differ in times, ports and request counts, so
    their evaluations are not compared byte for byte. What must agree is the
    verdict of every entry and, for cells, the observed category. Returns one
    row per entry of either evaluation.
    """
    before, after = _verdicts(reference), _verdicts(fresh)
    rows = []
    for name in list(before) + [name for name in after if name not in before]:
        rows.append({"entry": name, "reference": before.get(name), "fresh": after.get(name),
                     "same": name in before and name in after and before[name] == after[name]})
    return rows


def evaluate(spec, results_dir, mode=None):
    """Evaluate a results folder; the layout is taken from the specification unless `mode` names it."""
    if mode is None:
        mode = "cells" if "repeats_per_revision" in spec else "targets"
    if mode == "targets":
        return evaluate_targets(spec, results_dir)
    if mode == "cells":
        return evaluate_cells(spec, results_dir)
    raise ValueError("mode must be 'targets' or 'cells'")
