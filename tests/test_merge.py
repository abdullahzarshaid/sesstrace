"""The results of two attempts of one series, put together and evaluated as one.

In the release test of 17 November 2026 the first application series needed
two attempts: the image of one release could not be fetched in the first, and
that release was run again on its own. These tests rebuild the case from the
published records. The runs of the fixed release of T8 are taken out into a
second folder; the merge must give back a folder whose evaluation is the
published one.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from sesstrace.fileio import read_json, sha256_file
from sesstrace.replay import audit, evaluate, merge, spec as specification

CHECKS = Path(__file__).resolve().parents[1] / "checks"
PUBLISHED = CHECKS / "records" / "application_cells"
T8 = ("T8.logout", "T8.lifetime", "T8.credential_change", "T8.account_disabled")


def split(root):
    """Copy the published results into two attempts: all but the fixed release of T8, and that release alone."""
    source = PUBLISHED / "results"
    first, second = Path(root) / "attempt_1" / "results", Path(root) / "attempt_2" / "results"
    for path in sorted(source.rglob("*")):
        if path.is_file():
            relative = path.relative_to(source)
            of_second = relative.name == "setup_T8_fixed.txt" or (relative.parts[0] in T8 and relative.parts[1] == "fixed")
            destination = (second if of_second else first) / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(path), str(destination))
    return first, second


class TwoAttempts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = specification.load(CHECKS / "phase3" / "SPEC_CELLS_D.json")
        cls.scratch = tempfile.TemporaryDirectory(prefix="sesstrace-test-")
        cls.first, cls.second = split(cls.scratch.name)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def new_folder(self):
        folder = tempfile.TemporaryDirectory(prefix="sesstrace-test-")
        self.addCleanup(folder.cleanup)
        return Path(folder.name) / "merged"

    def test_one_attempt_alone_cannot_be_compared_with_the_published_records(self):
        rows = {row["cell"]: row for row in evaluate.evaluate(self.spec, self.first)["cells"]}
        for cell in T8:
            self.assertEqual((rows[cell]["verdict"], rows[cell]["observed_category"]), ("INCONCLUSIVE", "NO_VALID_RUN"))
        self.assertEqual(rows["T6.account_disabled"]["verdict"], "CONFIRMED")
        report = audit.audit_results(self.spec, self.first)
        self.assertEqual((report["runs"], len(report["runs_without_records"]), report["clean"]), (72, 12, False))
        report = audit.audit_results(self.spec, self.second)
        self.assertEqual((report["runs"], len(report["runs_without_records"])), (12, 72))

    def test_merged_attempts_give_the_published_evaluation(self):
        out = self.new_folder()
        record = merge.merge([self.first, self.second], out)
        self.assertEqual([len(attempt["files"]) for attempt in record["attempts"]], [151, 25])
        self.assertEqual(record["files"], 176)
        report = evaluate.evaluate(self.spec, out / "results")
        report["specification"] = "SPEC_CELLS_D.json"
        self.assertEqual(report, read_json(PUBLISHED / "evaluation.json"))
        checked = audit.audit_results(self.spec, out / "results")
        self.assertEqual((checked["runs"], checked["http_steps"], checked["problems"], checked["clean"]), (84, 792, [], True))

    def test_files_are_copied_unchanged_and_listed_with_their_hash(self):
        out = self.new_folder()
        record = merge.merge([self.first, self.second], out)
        self.assertEqual(record["attempts"][1]["results"], str(self.second))
        for attempt, source in zip(record["attempts"], (self.first, self.second)):
            for row in attempt["files"]:
                self.assertEqual(row["sha256"], sha256_file(source / row["file"]))
                self.assertEqual(row["sha256"], sha256_file(PUBLISHED / "results" / row["file"]))

    def test_a_file_in_two_attempts_stops_the_merge_before_anything_is_copied(self):
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as scratch:
            again = Path(scratch) / "attempt_3" / "results"
            run = Path("T8.logout") / "fixed" / "run_01" / "summary_T8.logout_fixed.json"
            (again / run).parent.mkdir(parents=True)
            shutil.copyfile(str(self.second / run), str(again / run))
            out = Path(scratch) / "merged"
            with self.assertRaises(merge.Overlap) as raised:
                merge.merge([self.first, self.second, again], out)
            self.assertIn("T8.logout/fixed/run_01/summary_T8.logout_fixed.json", str(raised.exception))
            self.assertFalse(out.exists())

    def test_existing_results_and_missing_folders_are_refused(self):
        out = self.new_folder()
        merge.merge([self.first], out)
        with self.assertRaises(ValueError):
            merge.merge([self.second], out)
        with self.assertRaises(ValueError):
            merge.merge([self.first, Path(self.scratch.name) / "no_such_attempt"], self.new_folder())


if __name__ == "__main__":
    unittest.main()
