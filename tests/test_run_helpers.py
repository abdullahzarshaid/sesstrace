"""The helpers of the container runners: plan.py, matrix_table.py and the shell functions of common.sh.

The runners themselves need a container engine and are exercised on a Linux
machine; what they read from the specifications is tested here, and the
shell functions that decide something are run against a stand-in for the
container engine.
"""
import importlib.util
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sesstrace.fileio import write_text

CHECKS = Path(__file__).resolve().parents[1] / "checks"
CELLS = CHECKS / "phase3" / "SPEC_CELLS.json"
APPLICATIONS = CHECKS / "phase3" / "SPEC_CELLS_D.json"
SECOND = CHECKS / "phase3b" / "SPEC_CELLS_3B.json"
THIRD = CHECKS / "phase3c" / "SPEC_CELLS_3C.json"


def plan(command, spec, *arguments):
    done = subprocess.run([sys.executable, str(CHECKS / "run" / "plan.py"), command, str(spec)] + list(arguments),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if done.returncode:
        raise AssertionError(done.stderr)
    return done.stdout.strip()


def shell_values(text):
    """Parse NAME=value lines the way a shell would."""
    return {line.partition("=")[0]: shlex.split(line.partition("=")[2])[0] for line in text.splitlines()}


class Plan(unittest.TestCase):
    def test_library_targets_and_cells(self):
        self.assertEqual(plan("targets", CELLS), "T1 T2 T3 T4")
        self.assertEqual(plan("cells", CELLS, "T4"), "T4.logout T4.concurrent_logout")
        self.assertEqual(plan("repeats", CELLS), "10")
        self.assertEqual(len(plan("images", CELLS).splitlines()), 3)
        for image in plan("images", CELLS).splitlines():
            self.assertRegex(image, r"^docker\.io/library/(node|python|ruby)@sha256:[0-9a-f]{64}$")

    def test_library_checkout_and_installation(self):
        values = shell_values(plan("library", CELLS, "T4", "fixed"))
        self.assertEqual(values["REPO"], "https://github.com/rack/rack-session.git")
        self.assertEqual(values["COMMIT"], "c28c4a8c1861d814e09f2ae48264ac4c40be2d3b")
        self.assertEqual(values["FETCH_BY_HASH"], "1")
        self.assertIn("gem build rack-session.gemspec", values["INSTALL"])
        self.assertEqual(shell_values(plan("library", CELLS, "T1", "vulnerable"))["FETCH_BY_HASH"], "0")

    def test_every_library_run_gets_its_own_port(self):
        lines = plan("library-runs", CELLS, "T4", "fixed").splitlines()
        self.assertEqual(len(lines), 20)
        self.assertEqual(lines[0], "01 T4.logout 19410 ruby /p2/hosts/rack_session_host.rb /tmp/checkout/T4/fixed 19410 3")
        self.assertEqual(lines[1].split()[:3], ["01", "T4.concurrent_logout", "19411"])
        self.assertEqual(lines[-1].split()[:3], ["10", "T4.concurrent_logout", "19501"])
        ports = [line.split()[2] for line in lines]
        self.assertEqual(len(set(ports)), len(ports))

    def test_host_files_named_by_the_specification_exist(self):
        for target in ("T1", "T2", "T3", "T4"):
            command = plan("library-runs", CELLS, target, "fixed").splitlines()[0].split()
            host = command[4]
            folder = {"/ext": CHECKS / "external_targets", "/p2": CHECKS / "phase2"}[host[:host.index("/hosts/")]]
            self.assertTrue((folder / "hosts" / Path(host).name).is_file(), host)

    def test_witness_run_uses_a_port_of_its_own(self):
        values = shell_values(plan("witness", CELLS, "T3", "vulnerable"))
        self.assertEqual(values["PORT"], "19800")
        self.assertEqual(values["HOSTCMD"], "python3 /p2/hosts/aiohttp_session_host.py /tmp/checkout/T3/vulnerable 19800 3")
        self.assertEqual(plan("witness-cells", CHECKS / "phase3" / "SPEC_WITNESS.json"),
                         "T1.lifetime T2.lifetime T3.lifetime T4.concurrent_logout")

    def test_application_values(self):
        values = shell_values(plan("application", APPLICATIONS, "T6"))
        self.assertEqual(values, {"APPPORT": "1881", "READY": "/", "SETUP": "setup/fuxa_setup.sh", "ADAPTER": "adapters/fuxa_adapter.py"})
        self.assertRegex(plan("image", APPLICATIONS, "T6", "fixed"), r"^docker\.io/frangoteam/fuxa@sha256:[0-9a-f]{64}$")
        self.assertNotEqual(plan("image", APPLICATIONS, "T6", "fixed"), plan("image", APPLICATIONS, "T6", "vulnerable"))
        self.assertEqual(shlex.split(plan("app-options", APPLICATIONS, "T8")), ["-e", "SESSION_DURATION=30"])
        self.assertEqual(plan("app-command", APPLICATIONS, "T8"), "")
        command = shlex.split(plan("app-command", APPLICATIONS, "T6"))
        self.assertEqual(command[:2], ["sh", "-c"])
        self.assertIn("refreshTokenExpiresIn = 30", command[2])

    def test_set_up_scripts_and_adapters_named_by_the_specifications_exist(self):
        for spec, base in ((APPLICATIONS, CHECKS / "phase3"), (SECOND, CHECKS), (THIRD, CHECKS)):
            for target in plan("targets", spec).split():
                values = shell_values(plan("application", spec, target))
                self.assertTrue((base / values["SETUP"]).is_file(), values["SETUP"])
                self.assertTrue((base / values["ADAPTER"]).is_file(), values["ADAPTER"])

    def test_third_application_series(self):
        self.assertEqual(plan("targets", THIRD), "T5")
        self.assertEqual(plan("cells", THIRD, "T5"), "T5.grant_withdrawn")
        self.assertEqual(plan("repeats", THIRD), "3")
        for revision in ("vulnerable", "fixed"):
            self.assertEqual(plan("image", THIRD, "T5", revision), plan("image", SECOND, "T5", revision))
        options = shlex.split(plan("app-options", THIRD, "T5"))
        self.assertIn("VIKUNJA_RATELIMIT_NOAUTHLIMIT=100", options)
        self.assertEqual(sorted(set(options) - set(shlex.split(plan("app-options", SECOND, "T5")))), ["VIKUNJA_RATELIMIT_NOAUTHLIMIT=100"])

    def test_matrix_lists_fifteen_images(self):
        lines = plan("matrix", CHECKS / "phase3" / "MATRIX_PLAN.json").splitlines()
        self.assertEqual(len(lines), 15)
        for line in lines:
            entry, base, dockerfile, python = line.split()
            self.assertTrue(dockerfile == "-" or (CHECKS / "phase3" / dockerfile).is_file(), dockerfile)


ENGINE = """#!/bin/sh
# Stand-in for the container engine: the exit status of pull and of image inspect comes from the environment.
case "$1" in
  pull) echo "pulling $2"; exit "${PULL_EXIT:-0}" ;;
  image) exit "${INSPECT_EXIT:-0}" ;;
esac
exit 9
"""
PINNED = "docker.io/library/python@sha256:" + "ab" * 32


def usable_shell():
    """bash, unless there is none or the only one is the launcher of another system."""
    found = shutil.which("bash")
    return None if found is None or "system32" in found.lower() else found


@unittest.skipUnless(usable_shell(), "needs bash")
class ShellHelpers(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="sesstrace-test-")
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        engine = self.scratch / "engine"
        write_text(engine, ENGINE)
        engine.chmod(engine.stat().st_mode | stat.S_IXUSR)
        self.engine = engine.as_posix()

    def shell(self, script, *arguments, **environment):
        settings = dict(os.environ, CONTAINER_ENGINE=self.engine, **environment)
        common = (CHECKS / "run" / "common.sh").as_posix()
        done = subprocess.run([usable_shell(), "-c", '. "$0"; ' + script, common] + list(arguments),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=settings)
        return done.returncode, done.stdout.strip(), done.stderr.strip()

    def fetch(self, image, **environment):
        record = self.scratch / "pull.txt"
        code, _, _ = self.shell('fetch_image "$1" "$2"', image, record.as_posix(), **environment)
        return code, record.read_text(encoding="utf-8")

    def test_image_that_can_be_pulled(self):
        code, record = self.fetch(PINNED)
        self.assertEqual(code, 0)
        self.assertEqual(record.strip(), "pulling " + PINNED)

    def test_registry_out_of_reach_and_the_pinned_image_already_here(self):
        code, record = self.fetch(PINNED, PULL_EXIT="1")
        self.assertEqual(code, 0)
        self.assertIn("pull failed; the image with this digest is already on this machine and is used", record)

    def test_registry_out_of_reach_and_no_such_image_here(self):
        code, record = self.fetch(PINNED, PULL_EXIT="1", INSPECT_EXIT="1")
        self.assertEqual(code, 1)
        self.assertNotIn("is used", record)

    def test_a_local_image_is_not_taken_for_a_tag(self):
        """A tag can point at another image tomorrow; only a digest names the same bytes."""
        code, record = self.fetch("docker.io/library/debian:12", PULL_EXIT="1")
        self.assertEqual(code, 1)
        self.assertNotIn("is used", record)

    def test_output_folder_is_new_and_starts_empty(self):
        out = (self.scratch / "out").as_posix()
        code, printed, _ = self.shell('new_output "$1"', out)
        self.assertEqual(code, 0)
        self.assertTrue(printed.endswith("/out"), printed)
        self.assertEqual(list((self.scratch / "out").iterdir()), [])
        code, _, message = self.shell('new_output "$1"', out)
        self.assertEqual(code, 4)
        self.assertIn("Refusing to reuse an existing output folder", message)


class MatrixTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("matrix_table", str(CHECKS / "run" / "matrix_table.py"))
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def image(self, root, name, distribution, tests="Ran 120 tests in 80.1s\n\nOK\n", tests_exit=0,
              verify="trace files equal to the reference: 12 of 12\nRESULT: identical\n", verify_exit=0):
        folder = Path(root) / "runs" / name
        write_text(folder / "environment.txt", 'id=%s\nPRETTY_NAME="%s"\nVERSION_ID="1"\npython_version=Python 3.12.3\n'
                   "libc_python=('glibc', '2.39')\nunit_tests_exit=%d\nlab_verify_exit=%d\n"
                   % (name, distribution, tests_exit, verify_exit))
        if tests is not None:
            write_text(folder / "unit_tests.txt", tests)
        if verify is not None:
            write_text(folder / "lab_verify.txt", verify)

    def test_rows_and_counts(self):
        with tempfile.TemporaryDirectory(prefix="sesstrace-test-") as root:
            self.image(root, "A01", "Debian GNU/Linux 12 (bookworm)")
            self.image(root, "A02", "Alpine Linux v3.24")
            self.image(root, "A03", "Debian GNU/Linux 12 (bookworm)")
            self.image(root, "A04", "Fedora Linux 45", tests="Ran 120 tests in 80.1s\n\nFAILED (failures=1)\n", tests_exit=1)
            self.image(root, "A05", "Arch Linux", verify="trace files equal to the reference: 11 of 12\nRESULT: DIFFERENT\n", verify_exit=1)
            self.image(root, "A06", "openSUSE Leap 16.0", tests=None, verify=None)
            (Path(root) / "runs" / "A07").mkdir()
            result = self.module.table(root)
        rows = {row["id"]: row for row in result["entries"]}
        self.assertEqual(result["counts"], {"IDENTICAL": 3, "DIFFERENT": 2, "FAILED": 2})
        self.assertEqual(result["distinct_distributions"], 5)
        self.assertEqual((rows["A01"]["tests_run"], rows["A01"]["traces_identical"]), (120, "12 of 12"))
        self.assertEqual(rows["A04"]["reasons"], ["unit tests: exit 1"])
        self.assertEqual(rows["A05"]["reasons"], ["laboratory: 11 of 12 trace files identical, exit 1"])
        self.assertEqual(rows["A06"]["reasons"], ["no output to compare"])
        self.assertIn("no environment record", rows["A07"]["reasons"][0])


if __name__ == "__main__":
    unittest.main()
