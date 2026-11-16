"""The specification checker and the freeze log."""
import copy
import tempfile
import unittest
from pathlib import Path

from sesstrace.fileio import write_text
from sesstrace.replay import freeze, spec as specification
from tests import scenarios


class SpecificationChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.good = scenarios.load("SPEC_CELLS_D.json")

    def broken(self, change):
        spec = copy.deepcopy(self.good)
        change(spec["targets"][0])
        return specification.problems(spec)

    def test_published_specification_has_no_problem(self):
        self.assertEqual(specification.problems(self.good), [])

    def test_missing_targets(self):
        self.assertEqual(specification.problems({}), ["the specification has no list 'targets'"])

    def test_unknown_step_kind(self):
        found = self.broken(lambda entry: entry["plan"].append({"phase": "replay", "do": "teleport"}))
        self.assertTrue(any("unknown kind 'teleport'" in line for line in found), found)

    def test_credential_used_before_login(self):
        def change(entry):
            entry["plan"].insert(0, {"phase": "setup", "do": "profile", "artifact": "carol1", "as": "carol", "checkpoint": "early"})
        found = self.broken(change)
        self.assertTrue(any("before any login issued it" in line for line in found), found)

    def test_checkpoint_without_expectation(self):
        found = self.broken(lambda entry: entry["expected"]["fixed"].pop("pre_alice"))
        self.assertTrue(any("no expected outcome for 'pre_alice' at the fixed revision" in line for line in found), found)

    def test_checkpoint_not_produced_by_the_plan(self):
        found = self.broken(lambda entry: entry["control_checkpoints"].append("control_that_no_step_makes"))
        self.assertTrue(any("is not produced by any step" in line for line in found), found)

    def test_outcome_word_outside_the_vocabulary(self):
        def change(entry):
            entry["expected"]["vulnerable"]["pre_alice"] = "maybe"
        found = self.broken(change)
        self.assertTrue(any("'maybe' is not an outcome word" in line for line in found), found)

    def test_duplicate_entry_id(self):
        spec = copy.deepcopy(self.good)
        spec["targets"].append(copy.deepcopy(spec["targets"][0]))
        self.assertTrue(any("used twice" in line for line in specification.problems(spec)))

    def test_entry_lookup(self):
        self.assertEqual(specification.entry(self.good, "T8.lifetime")["contract"], "lifetime")
        with self.assertRaises(KeyError):
            specification.entry(self.good, "T9.logout")


class FreezeLog(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="sesstrace-test-")
        self.root = Path(self.scratch.name)
        write_text(self.root / "spec.json", "{}\n")
        write_text(self.root / "scripts" / "run.sh", "echo run\n")

    def tearDown(self):
        self.scratch.cleanup()

    def test_block_checks_until_a_file_changes(self):
        freeze.write_block(self.root, "T1", ["spec.json", "scripts/run.sh"], "written before the first request")
        self.assertEqual(freeze.check(self.root, "T1"), [("spec.json", True), ("scripts/run.sh", True)])
        write_text(self.root / "spec.json", '{"edited": true}\n')
        self.assertEqual(freeze.check(self.root, "T1"), [("spec.json", False), ("scripts/run.sh", True)])

    def test_a_repair_adds_a_block_and_the_last_one_is_in_force(self):
        freeze.write_block(self.root, "T1", ["spec.json"], "first", utc="2026-01-01T00:00:00Z")
        write_text(self.root / "spec.json", '{"repaired": true}\n')
        freeze.write_block(self.root, "T1", ["spec.json"], "repair of the set-up", utc="2026-01-01T01:00:00Z")
        blocks = freeze.read_blocks(self.root / freeze.LOG_NAME)
        self.assertEqual([(block["name"], block["utc"], block["reason"]) for block in blocks],
                         [("T1", "2026-01-01T00:00:00Z", "first"), ("T1", "2026-01-01T01:00:00Z", "repair of the set-up")])
        self.assertNotEqual(blocks[0]["files"], blocks[1]["files"])
        self.assertEqual(freeze.check(self.root, "T1"), [("spec.json", True)])

    def test_missing_block_and_missing_file(self):
        freeze.write_block(self.root, "T1", ["spec.json"], "first")
        with self.assertRaises(freeze.NoSuchBlock):
            freeze.check(self.root, "T2")
        with self.assertRaises(FileNotFoundError):
            freeze.write_block(self.root, "T2", ["not_there.json"], "cannot be frozen")
        (self.root / "spec.json").unlink()
        self.assertEqual(freeze.check(self.root, "T1"), [("spec.json", False)])

    def test_block_name_is_one_word(self):
        with self.assertRaises(ValueError):
            freeze.write_block(self.root, "two words", ["spec.json"], "bad name")

    def test_plain_checksum_list(self):
        block = freeze.write_block(self.root, "T1", ["spec.json", "scripts/run.sh"], "first")
        lines = [line for line in block.splitlines() if len(line) > 66 and line[64:66] == "  "]
        write_text(self.root / "LIST.sha256", "\n".join(lines) + "\n")
        self.assertEqual(freeze.check_list(self.root / "LIST.sha256"), [("spec.json", True), ("scripts/run.sh", True)])


if __name__ == "__main__":
    unittest.main()
