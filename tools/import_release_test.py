"""Copy the result files of a release test into checks/release_test_<date>/.

Usage:  python tools/import_release_test.py <returned folder of the release test> <date, for example 20261117>

A release test runs every series again on a Linux machine and returns one
folder. Only the files that state a result are copied, unchanged: the
evaluation and the audit line of every series, the table of the distribution
images, the build record, the record of the host and of its unit tests. The
raw records of the runs stay with the authors. A list of SHA-256 values is
written beside the copies.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sesstrace.fileio import sha256_file, write_text  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[1]

# path inside the returned folder -> path inside the record folder
FILES = [
    ("environment.txt", "environment.txt"),
    ("host_unit_tests.txt", "host_unit_tests.txt"),
    ("outputs/libraries_1/evaluation.json", "evaluations/libraries.json"),
    ("outputs/libraries_1/audit.stdout.txt", "audits/libraries.txt"),
    ("outputs/applications_first_run_1/evaluation.json", "evaluations/applications_first_attempt_1.json"),
    ("outputs/applications_first_run_1/audit.stdout.txt", "audits/applications_first_attempt_1.txt"),
    ("outputs/applications_first_run_1/container_pull_T8_fixed.txt", "applications_first_attempt_1_pull_T8_fixed.txt"),
    ("outputs/applications_first_run_2_T8_fixed/evaluation.json", "evaluations/applications_first_attempt_2.json"),
    ("outputs/applications_first_run_2_T8_fixed/audit.stdout.txt", "audits/applications_first_attempt_2.txt"),
    ("outputs/applications_first_merged/evaluation.json", "evaluations/applications_first.json"),
    ("outputs/applications_first_merged/audit.stdout.txt", "audits/applications_first.txt"),
    ("outputs/applications_first_merged/MERGE_RECORD.txt", "applications_first_merge_record.txt"),
    ("outputs/applications_second_run_1/evaluation.json", "evaluations/applications_second.json"),
    ("outputs/applications_second_run_1/audit.stdout.txt", "audits/applications_second.txt"),
    ("outputs/witness_1/witness_evaluation.json", "evaluations/witness.json"),
    ("outputs/distributions_run_1/matrix_result.json", "evaluations/distributions.json"),
    ("outputs/distributions_run_1/matrix_table.txt", "distributions_table.txt"),
    ("outputs/distributions_build_1/build_records.txt", "distributions_build_records.txt"),
]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    returned, record = Path(sys.argv[1]), REPOSITORY / "checks" / ("release_test_" + sys.argv[2])
    copied = []
    for inside_returned, inside_record in FILES:
        destination = record / inside_record
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(returned / inside_returned), str(destination))
        copied.append(destination)
    lines = ["%s  %s" % (sha256_file(path), path.relative_to(record).as_posix()) for path in sorted(copied)]
    write_text(record / "SHA256SUMS.txt", "\n".join(lines) + "\n")
    print("%d files copied to %s" % (len(copied), record))


if __name__ == "__main__":
    main()
