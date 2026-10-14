"""Fail closed unless the original regression exhibits the specified change."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output
    runs = {}
    for label in ("before", "after"):
        result = json.loads((root / f"{label}_test_result.json").read_text())
        trace = [json.loads(line) for line in (root / f"{label}_trace.jsonl").read_text().splitlines()]
        assert result["tests_run"] == 1 and result["skipped"] == 0
        assert sum(row["event"] == "call" and row["function"] == result["selected_upstream_test"] for row in trace) == 1
        guard_calls = [row for row in trace if row["event"] == "call" and row["function"] == "update_ordered_and_reserved_qty"]
        closed_transitions = [row for row in trace if row["event"] == "return" and row["function"] == "update_status" and row["document"].get("status") == "Closed"]
        assert len(closed_transitions) == 1
        close_seq = closed_transitions[0]["sequence"]
        closed_order_name = closed_transitions[0]["document"]["name"]
        post_close = [row for row in trace if row["sequence"] > close_seq]
        calls_post_close = [row for row in guard_calls if row["sequence"] > close_seq]
        guard_returns_post_close = [row for row in post_close if row["event"] == "return" and row["function"] == "update_ordered_and_reserved_qty"]
        exceptions_post_close = [row for row in post_close if row["event"] == "exception"]
        if label == "before":
            assert not result["successful"] and result["errors"] == 1 and result["failures"] == 0
            assert not calls_post_close
            assert any(row["function"] == "validate" and row["exception"]["type"] == "InvalidStatusError" and "Closed" in row["exception"]["message"] for row in exceptions_post_close)
            assert any(row.get("validation_status_map", {}).get(closed_order_name) == "Closed" for row in exceptions_post_close)
        else:
            assert result["successful"] and result["errors"] == result["failures"] == 0
            assert len(calls_post_close) == 2
            assert all(row["document"].get("is_return") == 1 for row in calls_post_close)
            assert {row["document"].get("docstatus") for row in calls_post_close} == {1, 2}
            assert len(guard_returns_post_close) == 2
            assert all(row.get("guard_purchase_order", {}).get("status") == "Closed" and row["guard_purchase_order"]["name"] == closed_order_name and closed_order_name in row["linked_purchase_orders"] for row in guard_returns_post_close)
            assert any(row["function"] == "save" and not row["document"].get("is_return") and row["exception"]["type"] == "InvalidStatusError" and "Closed" in row["exception"]["message"] for row in exceptions_post_close)
        runs[label] = {
            "test_result": result,
            "all_guard_call_count": len(guard_calls),
            "guard_calls_after_order_closed": calls_post_close,
            "guard_returns_after_order_closed": guard_returns_post_close,
            "post_close_exception_functions": dict(Counter(row["function"] for row in exceptions_post_close)),
            "order_closed_trace_sequence": close_seq,
            "trace_sha256": hashlib.sha256((root / f"{label}_trace.jsonl").read_bytes()).hexdigest(),
        }
    summary = {
        "checks_passed": True,
        "before": "Original regression errors when the closed-order return is submitted: save validation raises InvalidStatusError before update_ordered_and_reserved_qty is reached for this return.",
        "after": "The unchanged original regression passes, including closed-order return submission and cancellation and rejection of a regular receipt. The updated guard is reached twice after order closure, for return submit and cancel.",
        "boundaries": [
            "One public upstream regression and its public generated fixtures; not a deployment prevalence study or six-state workflow reachability census.",
            "The original guard-level Cartesian experiment remains separate; pre-fix closed-return guard evaluation does not demonstrate an executable pre-fix application path.",
            "No production receipt retention policy or retrospective business requirement is inferred.",
            "Headless Document save/submit/cancel integration with MariaDB and Redis; browser UI, HTTP endpoints, concurrent users and the entire upstream test suite were not tested.",
            "Test execution is for correctness, not an application performance benchmark.",
        ],
        "runs": runs,
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"checks_passed": True, "guard_calls_before": runs["before"]["all_guard_call_count"], "guard_calls_after": runs["after"]["all_guard_call_count"]}))


if __name__ == "__main__":
    main()
