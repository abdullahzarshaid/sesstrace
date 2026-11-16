"""The two Python helpers of the container runners: plan.py and matrix_table.py.

The runners themselves need a container engine and are exercised on a Linux
machine; what they read from the specifications is tested here.
"""
import importlib.util
import shlex
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
        for spec, base in ((APPLICATIONS, CHECKS / "phase3"), (SECOND, CHECKS)):
            for target in plan("targets", spec).split():
                values = shell_values(plan("application", spec, target))
                self.assertTrue((base / values["SETUP"]).is_file(), values["SETUP"])
                self.assertTrue((base / values["ADAPTER"]).is_file(), values["ADAPTER"])

    def test_matrix_lists_fifteen_images(self):
        lines = plan("matrix", CHECKS / "phase3" / "MATRIX_PLAN.json").splitlines()
        self.assertEqual(len(lines), 15)
        for line in lines:
            entry, base, dockerfile, python = line.split()
            self.assertTrue(dockerfile == "-" or (CHECKS / "phase3" / dockerfile).is_file(), dockerfile)


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
