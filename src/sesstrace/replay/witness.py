"""Line witness: did the replay reach the line of the repair that refuses it?

A replay check shows that a copied credential is accepted before the repair
and refused after it. The line witness adds where the refusal happened. The
witness specification names, for a cell, the line (or branch) of the fixed
revision that refuses the replay and how often the plan of the cell must
reach it, both written down before the run. The run is then repeated once
with the line counter of the language switched on from outside the host
application:

    node     NODE_V8_COVERAGE; the raw record is a folder of V8 block counts
    python   the standard trace module; the raw record is {file: {line: count}}
    ruby     the standard Coverage library; the raw record holds line counts
             and branch counts per file

`counts` turns one raw record into the counts of the named lines. `evaluate`
compares outcomes and counts with the specification. `audit` checks the
witness runs against the plans of their cells, as is done for the cell runs.
"""
from pathlib import Path

from ..fileio import read_json, read_key_values
from .audit import audit_runs
from .evaluate import judge_summary, setup_problems
from .spec import VARIANTS

RESULTS = ("WITNESSED", "NOT_WITNESSED", "NOT_DONE")


def _node_counter(raw, checkout):
    """V8 reports counts for ranges of character offsets, nested inside each other."""
    ranges = {}
    for path in sorted(Path(raw).glob("*.json")):
        for script in read_json(path).get("result", []):
            for function in script["functions"]:
                ranges.setdefault(script["url"], []).extend(function["ranges"])

    def count(file, line, kind="line"):
        url = "file://" + str(Path(checkout) / file)
        if url not in ranges:
            return None
        lines = (Path(checkout) / file).read_text(encoding="utf-8").split("\n")
        text = lines[line - 1]
        # Offset of the first non-blank character of the line.
        offset = sum(len(earlier) + 1 for earlier in lines[:line - 1]) + len(text) - len(text.lstrip())
        around = [item for item in ranges[url] if item["startOffset"] <= offset < item["endOffset"]]
        if not around:
            return 0
        innermost = min(around, key=lambda item: item["endOffset"] - item["startOffset"])
        return innermost["count"]

    return count


def _python_counter(raw, checkout):
    data = read_json(raw)

    def count(file, line, kind="line"):
        return data.get(str(Path(checkout) / file), {}).get(str(line), 0)

    return count


def _ruby_counter(raw, checkout):
    data = read_json(raw)

    def count(file, line, kind="line"):
        coverage = data.get(str(Path(checkout) / file))
        if coverage is None:
            return None
        if kind == "branch_then":
            for branch in coverage["branches"]:
                if int(branch["branch"][2]) != line:
                    continue
                for target in branch["targets"]:
                    if target["target"][0] == "then":
                        return target["count"]
            return None
        lines = coverage["lines"]
        return lines[line - 1] if line - 1 < len(lines) else None

    return count


COUNTERS = {"node": _node_counter, "python": _python_counter, "ruby": _ruby_counter}


def wanted_lines(cell, variant):
    """The lines whose counts are reported for one revision of a witness cell."""
    if variant == "fixed":
        lines = [dict(cell["refusal"], role="refusal")]
        for file, numbers in cell["fix_lines_in_implementation_files"].items():
            lines += [{"file": file, "line": number, "kind": "line", "role": "fix_line"} for number in numbers]
        return lines
    if cell.get("vulnerable_counterpart"):
        return [dict(cell["vulnerable_counterpart"], role="vulnerable_counterpart")]
    return []


def counts(witness_spec, cell_id, variant, checkout, raw):
    """Read the raw record of one witness run and return the counts of the named lines."""
    cell = next(item for item in witness_spec["cells"] if item["cell"] == cell_id)
    report = {"cell": cell_id, "variant": variant, "runtime": cell["runtime"]}
    if not Path(raw).exists():
        report["error"] = "no raw counts were written"
        report["counts"] = []
        return report
    count = COUNTERS[cell["runtime"]](raw, checkout)
    report["counts"] = [dict(line, count=count(line["file"], line["line"], line["kind"]))
                        for line in wanted_lines(cell, variant)]
    return report


def _count_of(rows, role):
    for row in rows or []:
        if row["role"] == role:
            return True, row["count"]
    return False, None


def evaluate(cells_spec, witness_spec, out_dir):
    """Compare the witness runs with the specification.

    Layout of `out_dir`
        results/setup_<cell>_<revision>.txt
        results/<cell>/<revision>/witness/summary_<cell>_<revision>.json
        counts/counts_<cell>_<revision>.json
    """
    out_dir = Path(out_dir)
    entries = {entry["id"]: entry for entry in cells_spec["targets"]}
    rows = []
    for cell in witness_spec["cells"]:
        entry = entries[cell["cell"]]
        replay_checkpoint = entry["replay_checkpoints"][0]
        row = {"cell": cell["cell"], "runtime": cell["runtime"], "refusal": cell["refusal"],
               "expected_count_fixed": cell["expected_count_fixed"], "revisions": {}, "reasons": []}
        not_done = []
        for variant in VARIANTS:
            setup = read_key_values(out_dir / "results" / ("setup_%s_%s.txt" % (cell["cell"], variant)))
            problems = setup_problems(setup, entry[variant + "_commit"])
            replay = None
            summary_path = out_dir / "results" / cell["cell"] / variant / "witness" / ("summary_%s_%s.json" % (cell["cell"], variant))
            if summary_path.is_file():
                found, observed = judge_summary(entry, read_json(summary_path), variant)
                problems += found
                replay = observed.get(replay_checkpoint)
            else:
                problems.append("no summary written")
            wanted = entry["expected"][variant][replay_checkpoint]
            as_specified = not problems and replay == wanted
            counts_path = out_dir / "counts" / ("counts_%s_%s.json" % (cell["cell"], variant))
            counted = read_json(counts_path) if counts_path.is_file() else {"error": "no counts file"}
            if counted.get("error"):
                not_done.append("%s: %s" % (variant, counted["error"]))
            row["revisions"][variant] = {"run_valid": not problems, "problems": problems, "replay": replay,
                                         "expected_replay": wanted, "outcomes_as_specified": as_specified,
                                         "counts": counted.get("counts")}
            if not as_specified:
                row["reasons"].append("%s: outcomes not as specified (%s, replay %s)"
                                      % (variant, "; ".join(problems) or "valid run", replay))
        _, row["refusal_count_found"] = _count_of(row["revisions"]["fixed"]["counts"], "refusal")
        has_counterpart, counterpart = _count_of(row["revisions"]["vulnerable"]["counts"], "vulnerable_counterpart")
        if has_counterpart:
            row["vulnerable_counterpart_count_found"] = counterpart
        outcomes_hold = all(row["revisions"][variant]["outcomes_as_specified"] for variant in VARIANTS)
        if not_done and row["refusal_count_found"] is None:
            row["result"] = "NOT_DONE"
            row["reasons"] += not_done
        elif outcomes_hold and row["refusal_count_found"] == cell["expected_count_fixed"]:
            row["result"] = "WITNESSED"
        else:
            row["result"] = "NOT_WITNESSED"
            if row["refusal_count_found"] != cell["expected_count_fixed"]:
                row["reasons"].append("refusal count at the fixed revision: %s, stated in advance: %s"
                                      % (row["refusal_count_found"], cell["expected_count_fixed"]))
        rows.append(row)
    return {"cells": rows, "counts": {word: sum(1 for row in rows if row["result"] == word) for word in RESULTS}}


def run_folders(cells_spec, witness_spec, out_dir):
    """Yield (entry, revision, run label, folder) for the one witness run of every cell and revision."""
    entries = {entry["id"]: entry for entry in cells_spec["targets"]}
    for cell in witness_spec["cells"]:
        for variant in VARIANTS:
            yield entries[cell["cell"]], variant, "witness", Path(out_dir) / "results" / cell["cell"] / variant / "witness"


def audit(cells_spec, witness_spec, out_dir):
    """Check every witness run against the plan of its cell, using the trace. See `audit.audit_runs`."""
    return audit_runs(run_folders(cells_spec, witness_spec, out_dir))
