"""Summarize paired catalog access changes from the independently checked replay.

This consumes recorded access masks; it does not rerun the contract engine.
Counts of separately fetched blocks are not counts for a bundled endpoint.
"""
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

from audit_representations import part

ROOT = Path(__file__).resolve().parents[1]
NAMES = {0: "none", 1: "profile", 2: "timestamps", 3: "profile+timestamps"}


def main():
    path = ROOT / "results/v03/acquisition_access_traces.jsonl.gz"
    transitions, before, after = Counter(), Counter(), Counter()
    payload_delta = 0
    with gzip.open(path, "rt") as source:
        for line in source:
            row = json.loads(line)
            if part(row["document"], 17) != "test":
                continue
            a = row["masks"]["permissive"]["structural_order"]
            b = row["masks"]["strict_consignment"]["structural_order"]
            transitions[a, b] += 1
            before[a.bit_count()] += 1
            after[b.bit_count()] += 1
            payload_delta += ((bool(b & 1) - bool(a & 1)) * row["profile_bytes"]
                              + (bool(b & 2) - bool(a & 2)) * row["time_bytes"])
    n = sum(transitions.values())
    before_calls = sum(k * v for k, v in before.items())
    after_calls = sum(k * v for k, v in after.items())
    assert n == 50931
    assert before_calls == 52855 and after_calls == 80739
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Recorded paired structural-policy access masks on salt-17 test documents; no engine rerun",
        "source": str(path.relative_to(ROOT)),
        "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "cases": n,
        "transitions": [{"before": NAMES[a], "after": NAMES[b], "cases": count,
                         "fraction": count / n} for (a, b), count in sorted(transitions.items())],
        "query_count_distribution_before": dict(sorted(before.items())),
        "query_count_distribution_after": dict(sorted(after.items())),
        "separate_calls_before": before_calls,
        "separate_calls_after": after_calls,
        "additional_profile_reads": sum((bool(b & 1) - bool(a & 1)) * v for (a, b), v in transitions.items()),
        "additional_timestamp_reads": sum((bool(b & 2) - bool(a & 2)) * v for (a, b), v in transitions.items()),
        "additional_payload_bytes": payload_delta,
        "joint_full_fetch_calls": n,
        "separate_selective_minus_joint_full_calls": {
            "permissive": before_calls - n, "strict_consignment": after_calls - n},
        "rpc_scope": "Illustrative blocking single-case RPC mapping only: one call per selected block versus one call returning both blocks. No measured network latency, pipelining or batching.",
    }
    out = ROOT / "results/expanded/catalog_regression.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
