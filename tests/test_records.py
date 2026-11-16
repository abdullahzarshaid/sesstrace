"""The run records of the published checks, kept in checks/records/.

The records were written by the scripts frozen for each series. These tests
show that the package reads them the same way: the evaluator reproduces the
evaluation each series wrote at the time, byte for byte, and the audit finds
every run following its plan.
"""
import json
import unittest
from pathlib import Path

from sesstrace.fileio import read_json, sha256_file
from sesstrace.replay import audit, evaluate, freeze, witness, spec as specification

CHECKS = Path(__file__).resolve().parents[1] / "checks"
RECORDS = CHECKS / "records"
SERIES = read_json(CHECKS / "series.json")["series"]


def load(series):
    return specification.load(CHECKS / series["specification"])


class RecordsAreUnchanged(unittest.TestCase):
    def test_every_record_has_its_listed_hash(self):
        result = freeze.check_list(RECORDS / "SHA256SUMS.txt")
        self.assertEqual(len(result), 599)
        self.assertEqual([name for name, same in result if not same], [])

    def test_every_specification_has_its_frozen_hash(self):
        for series in SERIES:
            with self.subTest(specification=series["specification"]):
                path = CHECKS / series["specification"]
                self.assertEqual(sha256_file(path), series["specification_sha256"])

    def test_every_specification_passes_the_checker(self):
        for series in SERIES:
            with self.subTest(specification=series["specification"]):
                self.assertEqual(specification.problems(load(series)), [])

    def test_every_frozen_file_has_the_digest_of_its_freeze_log(self):
        """Specifications, hosts, adapters, set-up scripts, counting helpers and Dockerfiles are the frozen files."""
        logs = RECORDS / "freeze_logs"
        frozen = {"external_targets": {}, "phase2": {}, "phase3": {}, "phase3b": {}}
        for line in (logs / "libraries_single_run_1.sha256").read_text(encoding="utf-8").splitlines():
            frozen["external_targets"][line[66:]] = line[:64]
        for folder, log in (("phase2", "libraries_single_run_2.txt"), ("phase3", "cells_witness_distributions.txt"),
                            ("phase3b", "application_cells_second.txt")):
            # A later block replaces an earlier one, so the last digest of a path is the one in force.
            for block in freeze.read_blocks(logs / log):
                for digest, relative in block["files"]:
                    frozen[folder][relative] = digest
        checked = 0
        for folder, digests in frozen.items():
            for path in sorted((CHECKS / folder).rglob("*")):
                if path.is_file():
                    relative = path.relative_to(CHECKS / folder).as_posix()
                    with self.subTest(file=folder + "/" + relative):
                        self.assertEqual(sha256_file(path), digests.get(relative))
                    checked += 1
        self.assertEqual(checked, 36)


class EvaluationsAreReproduced(unittest.TestCase):
    def test_evaluator_writes_the_archived_evaluation(self):
        for series in SERIES:
            with self.subTest(series=series["name"]):
                report = evaluate.evaluate(load(series), RECORDS / series["name"] / "results")
                report["specification"] = Path(series["specification"]).name
                archived = (RECORDS / series["name"] / "evaluation.json").read_text(encoding="utf-8")
                self.assertEqual(report, json.loads(archived))
                self.assertEqual(json.dumps(report, indent=2) + "\n", archived)

    def test_combined_table_of_the_cells(self):
        reports = [read_json(RECORDS / series["name"] / "evaluation.json") for series in SERIES if series["layout"] == "cells"]
        cells = evaluate.combine(reports)
        self.assertEqual(len(cells), 23)
        self.assertEqual(len({row["target"] for row in cells}), 8)
        verdicts = [row["verdict"] for row in cells]
        self.assertEqual((verdicts.count("CONFIRMED"), verdicts.count("NOT_CONFIRMED"), verdicts.count("INCONCLUSIVE")), (21, 1, 1))
        categories = [row["observed_category"] for row in cells]
        self.assertEqual({word: categories.count(word) for word in sorted(set(categories))},
                         {"ACCEPTED_AT_BOTH": 8, "FLIPS": 6, "MIXED": 1, "NO_VALID_RUN": 1, "REFUSED_AT_BOTH": 7})
        by_cell = {row["cell"]: row for row in cells}
        self.assertEqual(by_cell["T7.logout"]["verdict"], "NOT_CONFIRMED")
        self.assertEqual(by_cell["T5.grant_withdrawn"]["verdict"], "INCONCLUSIVE")
        # The second attempt of this cell replaces the first, which had no valid run.
        self.assertEqual(by_cell["T7.credential_change"]["verdict"], "CONFIRMED")


class LineWitnessIsReproduced(unittest.TestCase):
    def test_witness_evaluation_equals_the_archived_one(self):
        report = witness.evaluate(specification.load(CHECKS / "phase3" / "SPEC_CELLS.json"),
                                  specification.load(CHECKS / "phase3" / "SPEC_WITNESS.json"), RECORDS / "line_witness")
        archived = read_json(RECORDS / "line_witness" / "evaluation.json")
        archived.pop("part")
        self.assertEqual(report, archived)
        self.assertEqual(report["counts"], {"WITNESSED": 4, "NOT_WITNESSED": 0, "NOT_DONE": 0})

    def test_distribution_table_of_the_laboratory(self):
        table = read_json(RECORDS / "distributions" / "evaluation.json")
        self.assertEqual(table["counts"], {"IDENTICAL": 15, "DIFFERENT": 0, "FAILED": 0, "NOT_APPLICABLE": 0})
        # Ten distribution releases; the five official Python images are Debian 13 again.
        self.assertEqual(len(table["entries"]), 15)
        self.assertEqual(len({row["distribution"] for row in table["entries"]}), 10)


class RunsFollowTheirPlans(unittest.TestCase):
    def test_audit_finds_no_problem(self):
        runs = requests = 0
        for series in SERIES:
            with self.subTest(series=series["name"]):
                report = audit.audit_results(load(series), RECORDS / series["name"] / "results")
                self.assertEqual(report["problems"], [])
                self.assertEqual(report["runs_without_records"], [])
                if series["layout"] == "cells":
                    runs += report["runs"]
                    requests += report["http_steps"]
                if series["name"] == "application_cells_second":
                    # A refused fresh login in the six runs of T5.grant_withdrawn: the request after it was not sent.
                    self.assertEqual(len(report["requests_not_sent"]), 6)
                else:
                    self.assertEqual(report["requests_not_sent"], [])
        self.assertEqual((runs, requests), (256, 2266))


if __name__ == "__main__":
    unittest.main()
