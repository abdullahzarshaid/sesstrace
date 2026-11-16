#!/usr/bin/env python3
"""Part C. Runs a host file under the standard trace module (line counting), outside the host file.
Usage: python3 python_trace_run.py <counts output json> <host file> <host arguments>...
A stop signal (SIGTERM) is turned into KeyboardInterrupt so that the host ends normally and the counts are written.
Only files under /tmp/checkout/ are kept in the output. Standard library only."""
import json, runpy, signal, sys, trace

out, host = sys.argv[1], sys.argv[2]
sys.argv = sys.argv[2:]


def stop(*_):
    raise KeyboardInterrupt()


signal.signal(signal.SIGTERM, stop)
tracer = trace.Trace(count=1, trace=0)
try:
    tracer.runctx("runpy.run_path(host, run_name='__main__')", {"runpy": runpy, "host": host}, {})
except KeyboardInterrupt:
    pass
finally:
    counts = {}
    for (fname, line), n in tracer.results().counts.items():
        if fname.startswith("/tmp/checkout/"):
            counts.setdefault(fname, {})[str(line)] = n
    with open(out, "w", encoding="utf-8") as f:
        json.dump(counts, f, indent=1, sort_keys=True)
