"""Compare a fresh laboratory run with the reference output kept in the package.

The reference files are the traces of the mechanisms M1 to M6 and the result
of the expiration fixtures M7 and M8 as archived with the first release of
the laboratory. A fresh run is expected to reproduce the twelve trace files
byte for byte and the expiration result as the same JSON value.
"""
import json
import tempfile
from pathlib import Path

from . import expiry, runner

REFERENCE_DIR = Path(__file__).resolve().parent / "reference"


def compare_traces(generated_dir, reference_dir=None):
    """Return {file name: True/False} for the reference trace files."""
    reference_dir = Path(reference_dir) if reference_dir else REFERENCE_DIR / "traces"
    generated_dir = Path(generated_dir)
    result = {}
    for ref in sorted(reference_dir.glob("*.json")):
        new = generated_dir / ref.name
        result[ref.name] = new.is_file() and new.read_bytes() == ref.read_bytes()
    return result


def verify(out_dir=None, quiet=True):
    """Run the laboratory and report whether it matches the reference.

    Returns a dict with the run summaries, the per-file comparison and one
    overall flag, `identical`.
    """
    with tempfile.TemporaryDirectory(prefix="sesstrace-") as scratch:
        target = Path(out_dir) if out_dir else Path(scratch)
        results = runner.run(str(target / "withdrawal"), quiet=quiet)
        traces = compare_traces(target / "withdrawal" / "traces")
        expiration = expiry.run()
        expiry.write_results(expiration, target / "expiration")
        reference = json.loads((REFERENCE_DIR / "expiry_results.json").read_text(encoding="utf-8"))
        expiry_equal = expiration == reference
    summary = results["summary"]
    return {
        "withdrawal": {k: summary[k] for k in ("n_mechanisms", "n_scenarios", "n_http_steps", "pov_confirmed",
                                               "pof_confirmed", "negative_control_failures", "all_clean")},
        "expiration": expiration["summary"],
        "trace_files": traces,
        "trace_files_identical": sum(traces.values()),
        "trace_files_total": len(traces),
        "expiration_result_equal": expiry_equal,
        "identical": bool(traces) and all(traces.values()) and expiry_equal
                     and summary["all_clean"] and expiration["summary"]["all_clean"],
    }
