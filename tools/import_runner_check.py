"""Copy the result files of the runner check of 18 November 2026 into checks/runner_check_20261118/.

Usage:  python tools/import_runner_check.py <returned folder of the runner check>

Only the files that state a result are copied, unchanged; the raw records of
the runs stay with the authors. A list of SHA-256 values is written beside the
copies.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sesstrace.fileio import sha256_file, write_text  # noqa: E402

RECORD = Path(__file__).resolve().parents[1] / "checks" / "runner_check_20261118"

# path inside the returned folder -> path inside the record folder
FILES = [
    ("environment.txt", "environment.txt"),
    ("host_unit_tests.txt", "host_unit_tests.txt"),
    ("outputs/step2_witness_1/witness_evaluation.json", "evaluations/witness.json"),
    ("outputs/step2_witness_1/audit.stdout.txt", "audits/witness.txt"),
    ("outputs/step3_half_a_vulnerable/evaluation.json", "evaluations/third_half_vulnerable.json"),
    ("outputs/step3_half_a_vulnerable/audit.stdout.txt", "audits/third_half_vulnerable.txt"),
    ("outputs/step3_half_b_fixed/evaluation.json", "evaluations/third_half_fixed.json"),
    ("outputs/step3_half_b_fixed/audit.stdout.txt", "audits/third_half_fixed.txt"),
    ("outputs/step3_merged/evaluation.json", "evaluations/third_merged.json"),
    ("outputs/step3_merged/audit.stdout.txt", "audits/third_merged.txt"),
    ("outputs/step5_nopull_1/container_pull_tool.txt", "pulls_refused/images_present_pull_tool.txt"),
    ("outputs/step5_nopull_1/container_pull_T5_vulnerable.txt", "pulls_refused/images_present_pull_T5_vulnerable.txt"),
    ("outputs/step5_nopull_1/container_pull_T5_fixed.txt", "pulls_refused/images_present_pull_T5_fixed.txt"),
    ("outputs/step5_nopull_2/environment_host.txt", "pulls_refused/images_removed_host_record.txt"),
    ("outputs/step6_build_1/build_records.txt", "distributions_build_records.txt"),
]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    returned = Path(sys.argv[1])
    copied = []
    for inside_returned, inside_record in FILES:
        destination = RECORD / inside_record
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(returned / inside_returned), str(destination))
        copied.append(destination)
    lines = ["%s  %s" % (sha256_file(path), path.relative_to(RECORD).as_posix()) for path in sorted(copied)]
    write_text(RECORD / "SHA256SUMS.txt", "\n".join(lines) + "\n")
    print("%d files copied to %s" % (len(copied), RECORD))


if __name__ == "__main__":
    main()
