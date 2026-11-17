"""Command line of SessTrace.

    sesstrace lab run        run the synthetic laboratory
    sesstrace lab verify     run it and compare with the reference output
    sesstrace spec check     check a specification file
    sesstrace spec list      list the entries of a specification
    sesstrace freeze write   record the hashes of the files of a check
    sesstrace freeze check   compare the files with the last record
    sesstrace run            drive one entry against a running target
    sesstrace merge          put the results of several attempts of a series into one folder
    sesstrace evaluate       turn the records of finished runs into verdicts
    sesstrace audit          check finished runs against their plan
    sesstrace report         print the table of one or more evaluations
    sesstrace compare        compare a fresh evaluation with a reference one
    sesstrace witness counts    counts of the named lines in one witness run
    sesstrace witness evaluate  compare the witness runs with their specification
    sesstrace witness audit     check the witness runs against the plans of their cells

Exit status: 0 when the command did its work and every check it makes held,
1 when a check did not hold, 2 for a wrong command line. For `run`, 1 means
that the records were written and at least one step ended in an error.
"""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .fileio import read_json, write_json
from .replay import audit, driver, evaluate, freeze, merge, witness, spec as specification


def _lab_run(args):
    from .lab import expiry, runner
    out = Path(args.out) if args.out else None
    results = runner.run(str(out / "withdrawal") if out else None, quiet=args.quiet)
    expiration = expiry.run()
    if out:
        expiry.write_results(expiration, out / "expiration")
    summary = expiration["summary"]
    if not args.quiet:
        print("expiration fixtures: scenarios=%d  HTTP steps=%d  controls %d/%d  all_clean=%s"
              % (summary["n_scenarios"], summary["n_http_steps"], summary["controls_passed"],
                 summary["controls_total"], summary["all_clean"]))
    return 0 if results["summary"]["all_clean"] and summary["all_clean"] else 1


def _lab_verify(args):
    from .lab import verify
    result = verify.verify(args.out)
    withdrawal, expiration = result["withdrawal"], result["expiration"]
    print("withdrawal mechanisms: %d scenarios, %d HTTP steps, all clean: %s"
          % (withdrawal["n_scenarios"], withdrawal["n_http_steps"], withdrawal["all_clean"]))
    print("expiration fixtures:   %d scenarios, %d HTTP steps, all clean: %s"
          % (expiration["n_scenarios"], expiration["n_http_steps"], expiration["all_clean"]))
    print("trace files equal to the reference: %d of %d" % (result["trace_files_identical"], result["trace_files_total"]))
    print("expiration result equal to the reference: %s" % result["expiration_result_equal"])
    for name, same in sorted(result["trace_files"].items()):
        if not same:
            print("  differs: " + name)
    print("RESULT: " + ("identical" if result["identical"] else "DIFFERENT"))
    return 0 if result["identical"] else 1


def _spec_check(args):
    found = specification.problems(specification.load(args.spec))
    for line in found:
        print(line)
    print("%s: %s" % (Path(args.spec).name, "no problem found" if not found else "%d problem(s)" % len(found)))
    return 1 if found else 0


def _spec_list(args):
    spec = specification.load(args.spec)
    repeats = spec.get("repeats_per_revision")
    print("%s: %d entries, %s" % (Path(args.spec).name, len(spec["targets"]),
                                  "%s runs per revision" % repeats if repeats else "one run per revision"))
    for entry in spec["targets"]:
        requests = len(specification.http_steps(entry["plan"]))
        print("  %-28s %-24s %2d requests  replay: %s" % (entry["id"], entry.get("package", ""), requests,
                                                         ", ".join(entry["replay_checkpoints"])))
    return 0


def _freeze_write(args):
    sys.stdout.write(freeze.write_block(args.root, args.name, args.files, args.reason))
    return 0


def _freeze_check(args):
    try:
        result = freeze.check(args.root, args.name)
    except freeze.NoSuchBlock:
        print("no freeze block named " + args.name)
        return 1
    for relative, same in result:
        print("%s: %s" % (relative, "OK" if same else "FAILED"))
    return 0 if result and all(same for _, same in result) else 1


def _run(args):
    spec = specification.load(args.spec)
    summary = driver.run_entry(spec, args.entry, args.revision, args.base, args.out)
    print(json.dumps({"entry": summary["target"], "revision": summary["variant"],
                      "checkpoints": {name: row["outcome"] for name, row in summary["checkpoints"].items()},
                      "invariant": summary["sesstrace_invariant"], "errors": len(summary["errors"])}))
    return 1 if summary["errors"] else 0


def _merge(args):
    try:
        record = merge.merge(args.results, args.out)
    except merge.Overlap as overlap:
        print("nothing was copied: %s" % overlap)
        return 1
    write_json(Path(args.out) / "merge_record.json", record)
    for attempt in record["attempts"]:
        print("%4d files from %s" % (len(attempt["files"]), attempt["results"]))
    print("%d files in %s" % (record["files"], Path(args.out) / "results"))
    return 0


def _evaluate(args):
    spec = specification.load(args.spec)
    report = evaluate.evaluate(spec, args.results, args.layout)
    report["specification"] = Path(args.spec).name
    write_json(args.out, report)
    if "cells" in report:
        print(json.dumps({row["cell"]: [row["verdict"], row["observed_category"]] for row in report["cells"]}))
    else:
        print(json.dumps({row["id"]: row["verdict"] for row in report["targets"]}))
    return 0


def _audit(args):
    return _audit_report(audit.audit_results(specification.load(args.spec), args.results), args.out)


def _audit_report(report, out):
    if out:
        write_json(out, report)
    for line in report["problems"]:
        print("PROBLEM  " + line)
    for line in report["runs_without_records"]:
        print("NO RECORD  " + line)
    for line in report["requests_not_sent"]:
        print("not sent  " + line)
    print("%d runs, %d requests read, %d problem(s), %d run(s) without records, %d request(s) not sent"
          % (report["runs"], report["http_steps"], len(report["problems"]),
             len(report["runs_without_records"]), len(report["requests_not_sent"])))
    return 0 if report["clean"] else 1


def _report(args):
    reports = [read_json(path) for path in args.files]
    with_cells = [report for report in reports if "cells" in report]
    if with_cells:
        cells = evaluate.combine(with_cells)
        print("%-26s %-18s %-18s %-14s %s" % ("cell", "expected", "observed", "verdict", "valid replays"))
        for row in cells:
            print("%-26s %-18s %-18s %-14s %s" % (row["cell"], row["expected_category"], row["observed_category"],
                                                 row["verdict"], row["count_text"]))
        verdicts = [row["verdict"] for row in cells]
        print("%d cells: %s" % (len(cells), ", ".join("%s %d" % (word, verdicts.count(word)) for word in evaluate.VERDICTS)))
    for report in reports:
        if "targets" not in report:
            continue
        print("%-8s %-28s %s" % ("entry", "package", "verdict"))
        for row in report["targets"]:
            print("%-8s %-28s %s" % (row["id"], row["package"], row["verdict"]))
            for reason in row["reasons"]:
                print("         " + reason)
    return 0


def _compare(args):
    rows = evaluate.compare(read_json(args.reference), read_json(args.fresh), counts=args.counts)

    def text(found):
        if found is None:
            return "(not in this evaluation)"
        return ", ".join(part for part in found if part is not None)

    for row in rows:
        print("%-9s %-26s reference: %-34s fresh: %s" % ("same" if row["same"] else "DIFFERENT", row["entry"],
                                                        text(row["reference"]), text(row["fresh"])))
    different = sum(1 for row in rows if not row["same"])
    print("%d entries, %d the same, %d different" % (len(rows), len(rows) - different, different))
    return 1 if different else 0


def _witness_counts(args):
    report = witness.counts(specification.load(args.spec), args.cell, args.revision, args.checkout, args.raw)
    write_json(args.out, report)
    print(json.dumps({"cell": args.cell, "revision": args.revision,
                      "refusal_or_counterpart": [row for row in report["counts"] if row["role"] != "fix_line"]}))
    return 1 if report.get("error") else 0


def _witness_evaluate(args):
    report = witness.evaluate(specification.load(args.cells), specification.load(args.spec), args.results)
    write_json(args.out, report)
    print(json.dumps({row["cell"]: [row["result"], row["refusal_count_found"], row["expected_count_fixed"]]
                      for row in report["cells"]}))
    return 0


def _witness_audit(args):
    report = witness.audit(specification.load(args.cells), specification.load(args.spec), args.results)
    return _audit_report(report, args.out)


def build_parser():
    parser = argparse.ArgumentParser(prog="sesstrace", description="Replay checks for the withdrawal of session authority.")
    parser.add_argument("--version", action="version", version="sesstrace " + __version__)
    commands = parser.add_subparsers(dest="command")
    commands.required = True

    lab = commands.add_parser("lab", help="the synthetic laboratory").add_subparsers(dest="lab_command")
    lab.required = True
    lab_run = lab.add_parser("run", help="run the eight mechanisms in both variants")
    lab_run.add_argument("--out", help="folder for the results and traces")
    lab_run.add_argument("--quiet", action="store_true")
    lab_run.set_defaults(handler=_lab_run)
    lab_verify = lab.add_parser("verify", help="run the laboratory and compare with the reference output")
    lab_verify.add_argument("--out", help="keep the generated files in this folder")
    lab_verify.set_defaults(handler=_lab_verify)

    spec = commands.add_parser("spec", help="specification files").add_subparsers(dest="spec_command")
    spec.required = True
    spec_check = spec.add_parser("check", help="check a specification file")
    spec_check.add_argument("spec")
    spec_check.set_defaults(handler=_spec_check)
    spec_list = spec.add_parser("list", help="list the entries of a specification")
    spec_list.add_argument("spec")
    spec_list.set_defaults(handler=_spec_list)

    frozen = commands.add_parser("freeze", help="freeze blocks").add_subparsers(dest="freeze_command")
    frozen.required = True
    freeze_write = frozen.add_parser("write", help="append a block with the hashes of the given files")
    freeze_write.add_argument("root", help="folder that holds FREEZE_LOG.txt")
    freeze_write.add_argument("name", help="name of the block, one word")
    freeze_write.add_argument("--reason", required=True)
    freeze_write.add_argument("files", nargs="+", help="paths relative to the folder")
    freeze_write.set_defaults(handler=_freeze_write)
    freeze_check = frozen.add_parser("check", help="compare the files with the last block of that name")
    freeze_check.add_argument("root")
    freeze_check.add_argument("name")
    freeze_check.set_defaults(handler=_freeze_check)

    run = commands.add_parser("run", help="drive one entry of a specification against a running target")
    run.add_argument("--spec", required=True)
    run.add_argument("--entry", required=True, help="id of the entry, for example T1.logout")
    run.add_argument("--revision", required=True, choices=specification.VARIANTS)
    run.add_argument("--base", required=True, help="base address of the target, for example http://127.0.0.1:18101")
    run.add_argument("--out", required=True, help="folder for the summary and the trace of this run")
    run.set_defaults(handler=_run)

    merging = commands.add_parser("merge", help="put the results of several attempts of one series into one folder")
    merging.add_argument("--out", required=True, help="new folder; it receives results/ and merge_record.json")
    merging.add_argument("results", nargs="+", help="results folders of the attempts, in the order they were run")
    merging.set_defaults(handler=_merge)

    evaluation = commands.add_parser("evaluate", help="turn the records of finished runs into verdicts")
    evaluation.add_argument("--spec", required=True)
    evaluation.add_argument("--results", required=True)
    evaluation.add_argument("--out", required=True, help="file for the evaluation (JSON)")
    evaluation.add_argument("--layout", choices=("targets", "cells"), help="default: taken from the specification")
    evaluation.set_defaults(handler=_evaluate)

    auditing = commands.add_parser("audit", help="check finished runs against their plan, using the traces")
    auditing.add_argument("--spec", required=True)
    auditing.add_argument("--results", required=True)
    auditing.add_argument("--out", help="file for the audit report (JSON)")
    auditing.set_defaults(handler=_audit)

    comparison = commands.add_parser("compare", help="compare the verdicts of a fresh evaluation with a reference one")
    comparison.add_argument("reference", help="evaluation file of the earlier run")
    comparison.add_argument("fresh", help="evaluation file of the new run")
    comparison.add_argument("--counts", action="store_true", help="the counts of valid replays must agree as well")
    comparison.set_defaults(handler=_compare)

    lines = commands.add_parser("witness", help="line witness").add_subparsers(dest="witness_command")
    lines.required = True
    witness_counts = lines.add_parser("counts", help="counts of the named lines in one witness run")
    witness_counts.add_argument("--spec", required=True, help="the witness specification")
    witness_counts.add_argument("--cell", required=True)
    witness_counts.add_argument("--revision", required=True, choices=specification.VARIANTS)
    witness_counts.add_argument("--checkout", required=True, help="folder of the checked-out library")
    witness_counts.add_argument("--raw", required=True, help="raw record written by the line counter")
    witness_counts.add_argument("--out", required=True)
    witness_counts.set_defaults(handler=_witness_counts)
    witness_evaluate = lines.add_parser("evaluate", help="compare the witness runs with their specification")
    witness_evaluate.add_argument("--cells", required=True, help="the cell specification the witness cells belong to")
    witness_evaluate.add_argument("--spec", required=True, help="the witness specification")
    witness_evaluate.add_argument("--results", required=True, help="folder that holds results/ and counts/")
    witness_evaluate.add_argument("--out", required=True)
    witness_evaluate.set_defaults(handler=_witness_evaluate)
    witness_audit = lines.add_parser("audit", help="check the witness runs against the plans of their cells")
    witness_audit.add_argument("--cells", required=True, help="the cell specification the witness cells belong to")
    witness_audit.add_argument("--spec", required=True, help="the witness specification")
    witness_audit.add_argument("--results", required=True, help="folder that holds results/")
    witness_audit.add_argument("--out", help="file for the audit report (JSON)")
    witness_audit.set_defaults(handler=_witness_audit)

    report = commands.add_parser("report", help="print the table of one or more evaluation files")
    report.add_argument("files", nargs="+", help="evaluation files, in the order their series were run")
    report.set_defaults(handler=_report)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, KeyError, ValueError) as error:
        print("sesstrace: %s" % error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
