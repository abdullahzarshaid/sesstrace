"""The command line, run the way a user runs it: python -m sesstrace ..."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sesstrace import __version__
from sesstrace.fileio import write_text
from tests import scenarios
from tests.stubs import ApplicationStub, SessionStub
from tests.test_merge import split

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"


def sesstrace(*arguments):
    environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONIOENCODING="utf-8")
    done = subprocess.run([sys.executable, "-m", "sesstrace"] + [str(argument) for argument in arguments],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=environment)
    return done.returncode, done.stdout, done.stderr


class CommandLine(unittest.TestCase):
    def test_version(self):
        code, out, _ = sesstrace("--version")
        self.assertEqual((code, out.strip()), (0, "sesstrace " + __version__))

    def test_wrong_command_line(self):
        code, _, err = sesstrace("evaluate", "--spec", "nowhere.json")
        self.assertEqual(code, 2)
        self.assertIn("required", err)

    def test_missing_file_is_reported_without_a_traceback(self):
        code, _, err = sesstrace("spec", "check", "nowhere.json")
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("sesstrace: "), err)
        self.assertNotIn("Traceback", err)

    def test_lab_verify(self):
        code, out, _ = sesstrace("lab", "verify")
        self.assertEqual(code, 0, out)
        self.assertIn("trace files equal to the reference: 12 of 12", out)
        self.assertIn("RESULT: identical", out)

    def test_spec_check_and_list(self):
        code, out, _ = sesstrace("spec", "check", CHECKS / "phase3" / "SPEC_CELLS.json")
        self.assertEqual((code, out.strip()), (0, "SPEC_CELLS.json: no problem found"))
        code, out, _ = sesstrace("spec", "list", CHECKS / "phase3" / "SPEC_CELLS.json")
        self.assertEqual(code, 0)
        self.assertIn("8 entries, 10 runs per revision", out)
        self.assertIn("T4.concurrent_logout", out)

    def test_evaluate_audit_and_report_on_the_published_records(self):
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            out_file = Path(scratch) / "evaluation.json"
            spec = CHECKS / "phase3" / "SPEC_CELLS_D.json"
            results = CHECKS / "records" / "application_cells" / "results"
            code, out, _ = sesstrace("evaluate", "--spec", spec, "--results", results, "--out", out_file)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["T8.lifetime"], ["CONFIRMED", "FLIPS"])
            archived = (CHECKS / "records" / "application_cells" / "evaluation.json").read_bytes()
            self.assertEqual(out_file.read_bytes(), archived)
            code, out, _ = sesstrace("audit", "--spec", spec, "--results", results)
            self.assertEqual(code, 0, out)
            self.assertIn("84 runs, 792 requests read, 0 problem(s)", out)
            code, out, _ = sesstrace("report", out_file)
            self.assertEqual(code, 0)
            self.assertIn("14 cells: CONFIRMED 12, NOT_CONFIRMED 1, INCONCLUSIVE 1", out)

    def test_compare_a_fresh_evaluation_with_the_published_one(self):
        published = CHECKS / "records" / "application_cells" / "evaluation.json"
        code, out, _ = sesstrace("compare", published, published)
        self.assertEqual(code, 0, out)
        self.assertIn("14 entries, 14 the same, 0 different", out)
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            fresh = json.loads(published.read_text(encoding="utf-8"))
            fresh["cells"][0]["verdict"] = "INCONCLUSIVE"
            fresh["cells"][1]["observed_category"] = "MIXED"
            del fresh["cells"][2]
            write_text(Path(scratch) / "fresh.json", json.dumps(fresh))
            code, out, _ = sesstrace("compare", published, Path(scratch) / "fresh.json")
        self.assertEqual(code, 1)
        self.assertIn("14 entries, 11 the same, 3 different", out)
        self.assertIn("(not in this evaluation)", out)

    def test_compare_can_include_the_counts_of_valid_replays(self):
        published = CHECKS / "records" / "application_cells" / "evaluation.json"
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            fresh = json.loads(published.read_text(encoding="utf-8"))
            row = fresh["cells"][0]
            self.assertEqual(row["count_text"], "vulnerable 3 of 3 accepted, 0 of 3 refused, fixed 3 of 3 accepted, 0 of 3 refused")
            row["count_text"] = "vulnerable 2 of 2 accepted, 0 of 2 refused, fixed 3 of 3 accepted, 0 of 3 refused"
            write_text(Path(scratch) / "fresh.json", json.dumps(fresh))
            code, out, _ = sesstrace("compare", published, Path(scratch) / "fresh.json")
            self.assertEqual(code, 0, out)
            self.assertIn("14 entries, 14 the same, 0 different", out)
            code, out, _ = sesstrace("compare", "--counts", published, Path(scratch) / "fresh.json")
        self.assertEqual(code, 1)
        self.assertIn("14 entries, 13 the same, 1 different", out)
        self.assertIn("vulnerable 2 of 2 accepted", out)
        code, out, _ = sesstrace("compare", "--counts", published, published)
        self.assertEqual(code, 0, out)

    def test_merge_two_attempts_then_evaluate_and_audit(self):
        spec = CHECKS / "phase3" / "SPEC_CELLS_D.json"
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            first, second = split(scratch)
            merged = Path(scratch) / "merged"
            code, out, _ = sesstrace("merge", "--out", merged, first, second)
            self.assertEqual(code, 0, out)
            self.assertIn(" 151 files from ", out)
            self.assertIn("  25 files from ", out)
            self.assertEqual(json.loads((merged / "merge_record.json").read_text(encoding="utf-8"))["files"], 176)
            code, _, _ = sesstrace("evaluate", "--spec", spec, "--results", merged / "results", "--out", merged / "evaluation.json")
            self.assertEqual(code, 0)
            published = CHECKS / "records" / "application_cells" / "evaluation.json"
            self.assertEqual((merged / "evaluation.json").read_bytes(), published.read_bytes())
            code, out, _ = sesstrace("audit", "--spec", spec, "--results", merged / "results")
            self.assertEqual(code, 0, out)
            self.assertIn("84 runs, 792 requests read, 0 problem(s), 0 run(s) without records", out)
            code, out, _ = sesstrace("merge", "--out", Path(scratch) / "again", first, first)
            self.assertEqual(code, 1)
            self.assertIn("nothing was copied", out)
            self.assertFalse((Path(scratch) / "again").exists())
            code, _, err = sesstrace("merge", "--out", merged, second)
            self.assertEqual(code, 2)
            self.assertIn("already holds results", err)

    def test_witness_audit_on_the_published_records(self):
        code, out, _ = sesstrace("witness", "audit", "--cells", CHECKS / "phase3" / "SPEC_CELLS.json",
                                 "--spec", CHECKS / "phase3" / "SPEC_WITNESS.json", "--results", CHECKS / "records" / "line_witness")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.strip(), "8 runs, 64 requests read, 0 problem(s), 0 run(s) without records, 0 request(s) not sent")

    def test_freeze_write_then_check(self):
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            write_text(Path(scratch) / "spec.json", "{}\n")
            code, out, _ = sesstrace("freeze", "write", scratch, "T1", "--reason", "before the first request", "spec.json")
            self.assertEqual(code, 0)
            self.assertIn("=== FREEZE T1 utc=", out)
            self.assertEqual(sesstrace("freeze", "check", scratch, "T1")[:2], (0, "spec.json: OK\n"))
            write_text(Path(scratch) / "spec.json", "{ }\n")
            self.assertEqual(sesstrace("freeze", "check", scratch, "T1")[:2], (1, "spec.json: FAILED\n"))
            self.assertEqual(sesstrace("freeze", "check", scratch, "T2")[:2], (1, "no freeze block named T2\n"))

    def test_run_writes_a_summary_and_a_trace_without_the_cookie(self):
        spec = scenarios.shortened(scenarios.load("SPEC_CELLS_D.json"), only=["T7.logout"], repeats=1)
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            spec_file = Path(scratch) / "spec.json"
            write_text(spec_file, json.dumps(spec))
            with ApplicationStub(logout_revokes=True) as stub:
                code, out, err = sesstrace("run", "--spec", spec_file, "--entry", "T7.logout", "--revision", "fixed",
                                           "--base", stub.base_url, "--out", Path(scratch) / "run")
                issued = list(stub.sessions)
            self.assertEqual(code, 0, err)
            line = json.loads(out)
            self.assertEqual(line["invariant"], {"replay_after_logout": "PASS"})
            self.assertEqual(line["errors"], 0)
            summary = (Path(scratch) / "run" / "summary_T7.logout_fixed.json").read_text(encoding="utf-8")
            trace = (Path(scratch) / "run" / "trace_T7.logout_fixed.json").read_text(encoding="utf-8")
            self.assertTrue(issued)
            for cookie in issued:
                self.assertNotIn(cookie, summary)
                self.assertNotIn(cookie, trace)
            self.assertNotIn(stub.base_url, trace)

    def test_run_ends_with_status_1_when_a_step_ended_in_an_error(self):
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            # The second login of the plan is answered with an error, as a rate limit would.
            with SessionStub("store", fixed=True, break_login_after=1) as stub:
                code, out, err = sesstrace("run", "--spec", CHECKS / "phase3" / "SPEC_CELLS.json", "--entry", "T1.logout",
                                           "--revision", "fixed", "--base", stub.base_url, "--out", Path(scratch) / "run")
            self.assertEqual(code, 1, err)
            self.assertGreater(json.loads(out)["errors"], 0)
            self.assertTrue((Path(scratch) / "run" / "summary_T1.logout_fixed.json").is_file())
            self.assertTrue((Path(scratch) / "run" / "trace_T1.logout_fixed.json").is_file())


if __name__ == "__main__":
    unittest.main()
