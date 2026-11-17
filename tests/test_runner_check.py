"""The check of the changed runners of 18 November 2026, read from the result files in checks/runner_check_20261118/."""
import re
import unittest
from pathlib import Path

from sesstrace.fileio import read_json
from sesstrace.replay import evaluate, freeze

CHECKS = Path(__file__).resolve().parents[1] / "checks"
RECORDS = CHECKS / "records"
CHECK = CHECKS / "runner_check_20261118"
USED = "pull failed; the image with this digest is already on this machine and is used"


def last_lines(name):
    return (CHECK / "audits" / (name + ".txt")).read_text(encoding="utf-8").splitlines()[-2:]


class RunnerCheck(unittest.TestCase):
    def test_copied_files_have_their_listed_hash(self):
        result = freeze.check_list(CHECK / "SHA256SUMS.txt")
        self.assertEqual(len(result), 15)
        self.assertEqual([name for name, same in result if not same], [])

    def test_two_halves_put_together_give_the_published_cell(self):
        published = read_json(RECORDS / "application_cells_third" / "evaluation.json")
        merged = read_json(CHECK / "evaluations" / "third_merged.json")
        rows = evaluate.compare(published, merged, counts=True)
        self.assertEqual([(row["entry"], row["same"]) for row in rows], [("T5.grant_withdrawn", True)])
        self.assertEqual(last_lines("third_merged"),
                         ["6 runs, 60 requests read, 0 problem(s), 0 run(s) without records, 0 request(s) not sent", "audit_exit=0"])

    def test_each_half_alone_has_no_valid_run_for_the_cell(self):
        for name, release in (("third_half_vulnerable", "vulnerable"), ("third_half_fixed", "fixed")):
            with self.subTest(half=name):
                row = read_json(CHECK / "evaluations" / (name + ".json"))["cells"][0]
                other = "fixed" if release == "vulnerable" else "vulnerable"
                self.assertEqual((row["verdict"], row["observed_category"]), ("INCONCLUSIVE", "NO_VALID_RUN"))
                self.assertEqual((row["revisions"][release]["valid_runs"], row["revisions"][other]["valid_runs"]), (3, 0))
                self.assertEqual(last_lines(name),
                                 ["3 runs, 30 requests read, 0 problem(s), 3 run(s) without records, 0 request(s) not sent", "audit_exit=1"])

    def test_line_witness_and_its_audit(self):
        def rows(report):
            return {row["cell"]: (row["result"], row["refusal_count_found"], row["expected_count_fixed"]) for row in report["cells"]}
        self.assertEqual(rows(read_json(CHECK / "evaluations" / "witness.json")),
                         rows(read_json(RECORDS / "line_witness" / "evaluation.json")))
        self.assertEqual(last_lines("witness"),
                         ["8 runs, 64 requests read, 0 problem(s), 0 run(s) without records, 0 request(s) not sent", "audit_exit=0"])

    def test_refused_pull_uses_the_image_on_the_machine_or_skips_the_release(self):
        for name in ("tool", "T5_vulnerable", "T5_fixed"):
            lines = (CHECK / "pulls_refused" / ("images_present_pull_%s.txt" % name)).read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[-1], USED, name)
        record = (CHECK / "pulls_refused" / "images_removed_host_record.txt").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"^Could not pull docker\.io/vikunja/vikunja@sha256:[0-9a-f]{64}$", record, re.M)), 2)

    def test_build_record_states_the_steps_taken_from_the_cache(self):
        record = (CHECK / "distributions_build_records.txt").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"^A\d\d_\w+ build_exit=0 steps_from_cache=1$", record, re.M)), 10)
        self.assertEqual(len(re.findall(r"^A\d\d_\w+ pull_exit=0$", record, re.M)), 15)

    def test_freeze_blocks_were_written_before_their_steps(self):
        blocks = {block["name"]: block["utc"] for block in freeze.read_blocks(CHECK / "FREEZE_LOG.txt")}
        self.assertEqual(sorted(blocks), ["applications_third", "witness"])
        started = {}
        for line in (CHECK / "environment.txt").read_text(encoding="utf-8").splitlines():
            name, _, times = line.strip().partition(": ")
            if " to " in times:
                started[name] = times.split(" to ")[0]
        self.assertLess(blocks["witness"], started["step2_witness_1"])
        self.assertLess(blocks["applications_third"], started["step3_boot_1"])


if __name__ == "__main__":
    unittest.main()
