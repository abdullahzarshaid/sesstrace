"""The release test of 17 November 2026: a fresh run of every series, compared with the published records.

The evaluations the runners wrote on that day are kept in
checks/release_test_20261117/. These tests compare them with the evaluations
in checks/records/, cell by cell and with the counts of valid replays.
"""
import unittest
from pathlib import Path

from sesstrace.fileio import read_json
from sesstrace.replay import evaluate, freeze

CHECKS = Path(__file__).resolve().parents[1] / "checks"
RECORDS = CHECKS / "records"
FRESH = CHECKS / "release_test_20261117"
SERIES = (("library_cells", "libraries", 8), ("application_cells", "applications_first", 14),
          ("application_cells_second", "applications_second", 2))


def differing(published, fresh):
    return [row["entry"] for row in evaluate.compare(published, fresh, counts=True) if not row["same"]]


class FreshRunEqualsThePublishedRecords(unittest.TestCase):
    def test_copied_files_have_their_listed_hash(self):
        result = freeze.check_list(FRESH / "SHA256SUMS.txt")
        self.assertEqual(len(result), 18)
        self.assertEqual([name for name, same in result if not same], [])

    def test_every_cell_has_the_published_verdict_category_and_counts(self):
        for published, fresh, cells in SERIES:
            with self.subTest(series=published):
                rows = evaluate.compare(read_json(RECORDS / published / "evaluation.json"),
                                        read_json(FRESH / "evaluations" / (fresh + ".json")), counts=True)
                self.assertEqual(len(rows), cells)
                self.assertEqual([row["entry"] for row in rows if not row["same"]], [])

    def test_first_attempt_alone_lacks_one_release_of_one_target(self):
        published = read_json(RECORDS / "application_cells" / "evaluation.json")
        first = read_json(FRESH / "evaluations" / "applications_first_attempt_1.json")
        self.assertEqual(differing(published, first), ["T8.logout", "T8.lifetime", "T8.credential_change", "T8.account_disabled"])
        for row in first["cells"]:
            if row["target"] == "T8":
                self.assertEqual((row["verdict"], row["revisions"]["vulnerable"]["valid_runs"], row["revisions"]["fixed"]["valid_runs"]),
                                 ("INCONCLUSIVE", 3, 0))

    def test_audit_lines_of_the_fresh_runs(self):
        lines = {name: (FRESH / "audits" / (name + ".txt")).read_text(encoding="utf-8").splitlines()[-2:]
                 for name in ("libraries", "applications_first", "applications_second", "applications_first_attempt_1")}
        self.assertEqual(lines["libraries"],
                         ["160 runs, 1360 requests read, 0 problem(s), 0 run(s) without records, 0 request(s) not sent", "audit_exit=0"])
        self.assertEqual(lines["applications_first"],
                         ["84 runs, 792 requests read, 0 problem(s), 0 run(s) without records, 0 request(s) not sent", "audit_exit=0"])
        self.assertEqual(lines["applications_second"],
                         ["12 runs, 114 requests read, 0 problem(s), 0 run(s) without records, 6 request(s) not sent", "audit_exit=0"])
        self.assertEqual(lines["applications_first_attempt_1"],
                         ["72 runs, 678 requests read, 0 problem(s), 12 run(s) without records, 0 request(s) not sent", "audit_exit=1"])

    def test_line_witness(self):
        def rows(report):
            return {row["cell"]: (row["result"], row["refusal_count_found"], row["expected_count_fixed"],
                                  row.get("vulnerable_counterpart_count_found")) for row in report["cells"]}
        fresh = rows(read_json(FRESH / "evaluations" / "witness.json"))
        self.assertEqual(fresh, rows(read_json(RECORDS / "line_witness" / "evaluation.json")))
        self.assertEqual([fresh[cell][:2] for cell in ("T1.lifetime", "T2.lifetime", "T3.lifetime", "T4.concurrent_logout")],
                         [("WITNESSED", 1), ("WITNESSED", 1), ("WITNESSED", 4), ("WITNESSED", 1)])

    def test_laboratory_on_the_fifteen_images(self):
        fresh = {row["id"]: row for row in read_json(FRESH / "evaluations" / "distributions.json")["entries"]}
        published = {row["id"]: row for row in read_json(RECORDS / "distributions" / "evaluation.json")["entries"]}
        self.assertEqual(sorted(fresh), sorted(published))
        self.assertEqual(len(fresh), 15)
        for name, row in fresh.items():
            with self.subTest(image=name):
                self.assertEqual((row["result"], row["tests_run"], row["traces_identical"]), ("IDENTICAL", 112, "12 of 12"))
                self.assertEqual(published[name]["traces_identical"], "12 of 12")
        # Two derived images were built again and installed a newer patch release of Python.
        self.assertEqual(sorted(name for name in fresh if fresh[name]["python_version"] != published[name]["python_version"]),
                         ["A06_almalinux9", "A10_amazonlinux2023"])
        self.assertEqual(len({row["distribution"] for row in fresh.values()}), 10)

    def test_freeze_blocks_were_written_before_their_series(self):
        blocks = {block["name"]: block["utc"] for block in freeze.read_blocks(FRESH / "FREEZE_LOG.txt")}
        self.assertEqual(sorted(blocks), ["applications_first", "applications_second", "distributions", "libraries", "witness"])
        started = {}
        for line in (FRESH / "environment.txt").read_text(encoding="utf-8").splitlines():
            name, _, times = line.strip().partition(": ")
            if times and " to " in times:
                started[name] = times.split(" to ")[0]
        for block, series in (("distributions", "distributions_run_1"), ("libraries", "libraries_1"), ("witness", "witness_1"),
                              ("applications_first", "applications_first_run_1"), ("applications_second", "applications_second_run_1")):
            with self.subTest(block=block):
                self.assertLess(blocks[block], started[series])


if __name__ == "__main__":
    unittest.main()
