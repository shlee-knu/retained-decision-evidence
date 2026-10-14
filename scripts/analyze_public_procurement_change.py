#!/usr/bin/env python3
"""Bounded, offline re-execution of ERPNext PR 58126's changed order guard.

The third-party method is extracted without rewriting its AST and executed with
explicit environment stubs. Only this guard is studied; a successful stub call
is not a successful ERPNext save/submit/cancel. The diagnostic model is separate
from the executed upstream method. No BPI fields or counts enter this experiment.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from itertools import combinations, product
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from logistics_validation.focused_diagnostics import FiniteDiagnostics, projection

DEFAULT_OUT = ROOT / "results/beta_improvement_20261012/public_change"
PROTOCOL_PATH = ROOT / "configs/public_procurement_change_protocol.json"
BLOCKS = ("purchase_order.status", "is_return")
STATUSES = ("To Bill", "Closed", "Cancelled")
STATES = tuple(product(STATUSES, (False, True)))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in rows), encoding="utf-8")


def verified_inputs(source_root: Path = DEFAULT_OUT):
    protocol = json.loads(PROTOCOL_PATH.read_text())
    lock = json.loads((source_root / "protocol_lock.json").read_text())
    if digest(PROTOCOL_PATH) != lock["sha256"]:
        raise ValueError("Prospective protocol changed after lock")
    manifest = json.loads((source_root / "source_manifest.json").read_text())
    for entry in manifest["files"]:
        p = source_root / entry["path"]
        if digest(p) != entry["sha256"] or p.stat().st_size != entry["bytes"]:
            raise ValueError(f"Archived upstream source hash mismatch: {entry['path']}")
    src = protocol["source"]
    commits = json.loads((source_root / "sources/pr_58126_commits.json").read_text())
    changed = next(c for c in commits if c["sha"] == src["after_commit"])
    if [p["sha"] for p in changed["parents"]] != [src["before_commit"]]:
        raise ValueError("The before source is not the changed commit's direct parent")
    pr = json.loads((source_root / "sources/pr_58126.json").read_text())
    if not pr["merged"] or pr["merge_commit_sha"] != src["merged_commit"]:
        raise ValueError("Archived PR merge evidence disagrees with protocol")
    # The bounded status literals must belong to the pinned real document schema.
    schema_path = source_root / "sources" / src["after_commit"] / "erpnext/buying/doctype/purchase_order/purchase_order.json"
    schema = json.loads(schema_path.read_text())
    options = next(f["options"].splitlines() for f in schema["fields"] if f["fieldname"] == "status")
    if not set(STATUSES) <= set(options):
        raise ValueError("A selected status is not a published Purchase Order status")
    if protocol["bounded_domain"]["blocks"] != list(BLOCKS) or protocol["bounded_domain"]["values"] != [list(STATUSES), [False, True]]:
        raise ValueError("Implemented selected domain differs from protocol")
    return protocol, lock, manifest


class GuardRejected(Exception):
    """The mocked Frappe InvalidStatusError; no other exceptions are swallowed."""


class SourceGuard:
    """The complete unmodified upstream method with declared external stubs."""

    def __init__(self, source: Path, classname: str, method: str):
        source_text = source.read_text()
        tree = ast.parse(source_text, filename=str(source))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == classname)
        node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method)
        if node.decorator_list or any(isinstance(n, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)) for n in ast.walk(node)):
            raise ValueError("Extraction boundary changed; manual protocol review required")
        self.code = compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec")
        # No AST nodes, branch expressions, or called method arguments are changed.
        self.metadata = {
            "source_path": source.relative_to(ROOT).as_posix() if source.is_relative_to(ROOT) else str(source),
            "source_sha256": digest(source),
            "class": classname,
            "method": method,
            "line_start": node.lineno,
            "line_end": node.end_lineno,
            "method_text_sha256": hashlib.sha256(ast.get_source_segment(source_text, node).encode()).hexdigest(),
            "method_ast_sha256": hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest(),
            "ast_transformed": False,
        }
        self.method = method

    def execute(self, state):
        status, is_return = state
        if status not in STATUSES or type(is_return) is not bool:
            raise ValueError("Outside the declared input domain")
        events = []
        item = SimpleNamespace(purchase_order="PO-PUBLIC-CASE", purchase_order_item="PO-ITEM-1")

        def document_get(key):
            if key == "items":
                return [item]
            if key == "is_return":
                events.append({"operation": "read_is_return", "value": is_return})
                return is_return
            raise AssertionError(f"Unexpected document access: {key}")

        def update_ordered_qty(rows):
            if rows != ["PO-ITEM-1"]:
                raise AssertionError("Unexpected ordered quantity update arguments")
            events.append({"operation": "update_ordered_qty_stub", "rows": rows})

        po = SimpleNamespace(status=status, update_ordered_qty=update_ordered_qty)

        def get_lazy_doc(doctype, name):
            if (doctype, name) != ("Purchase Order", "PO-PUBLIC-CASE"):
                raise AssertionError("Unexpected source lookup")
            events.append({"operation": "get_lazy_doc", "doctype": doctype, "name": name, "status": status})
            return po

        def throw(message, exception):
            if exception is not GuardRejected:
                raise AssertionError("Unexpected source exception class")
            events.append({"operation": "throw", "message": message})
            raise GuardRejected(message)

        frappe = SimpleNamespace(get_lazy_doc=get_lazy_doc, throw=throw,
                                 bold=lambda x: x, InvalidStatusError=GuardRejected)
        env = {"__builtins__": {}, "frappe": frappe, "_": lambda x: x}
        exec(self.code, env)
        document = SimpleNamespace(doctype="Purchase Receipt", get=document_get)
        try:
            env[self.method](document)
            passed = True
        except GuardRejected:
            passed = False
        updates = sum(e["operation"] == "update_ordered_qty_stub" for e in events)
        if updates != int(passed):
            raise AssertionError("The selected guard did not reach exactly the expected stub boundary")
        return {"guard_passed": passed, "events": events}


class GuardProblem:
    """Two-block finite adapter; does not read the source oracle's outputs."""
    blocks, count = BLOCKS, 2

    def all_states(self):
        for state in STATES:
            yield (), state

    def label(self, base, state, new):
        if base:
            raise ValueError("This model has no retained activity-order base")
        status, is_return = state
        # Declarative version of the two selected predicates, independently
        # checked against execution of the original method at every state.
        if new:
            return status != "Cancelled" and (status != "Closed" or is_return)
        return status not in ("Closed", "Cancelled")


def all_queries():
    """All partial observations in the finite domain, including both old claims."""
    for mask in range(4):
        projections = sorted({projection(s, mask) for s in STATES}, key=repr)
        for observed in projections:
            for old in (False, True):
                yield {"base": (), "mask": mask, "observed": observed, "old_verdict": old}


def source_reference_diagnosis(query, source_labels):
    """Independent pair-separation checker driven only by executed source labels."""
    fiber = [s for s in STATES if projection(s, query["mask"]) == query["observed"]]
    old = query["old_verdict"]
    if not fiber or any(source_labels[s][0] != old for s in fiber) or type(old) is not bool:
        return {"status": "invalid_receipt", "robust_masks": []}
    new_values = {source_labels[s][1] for s in fiber}
    if len(new_values) == 1:
        return {"status": "safe" if new_values == {old} else "stale_verdict", "robust_masks": [0]}
    opposed = [(a, b) for a, b in combinations(fiber, 2) if source_labels[a][1] != source_labels[b][1]]
    robust = []
    for additional in range(4):
        if additional & query["mask"]:
            continue
        # A query set works iff every opposed source-executed pair differs in
        # at least one acquired coordinate. This is separate from engine fibers.
        if all(any(additional & (1 << i) and a[i] != b[i] for i in range(2)) for a, b in opposed):
            robust.append(additional)
    minimal = [m for m in robust if not any(n != m and n & m == n for n in robust)]
    return {"status": "insufficient", "robust_masks": sorted(minimal)}


def check_witnesses(query, result, source_labels):
    if result["status"] != "insufficient":
        if result["witnesses"] is not None:
            raise AssertionError("Unexpected witnesses on an unambiguous/invalid result")
        return
    pair = tuple(tuple(s) for s in result["witnesses"])
    if len(pair) != 2 or any(s not in source_labels for s in pair):
        raise AssertionError("Unsupported witness")
    if any(projection(s, query["mask"]) != query["observed"] for s in pair):
        raise AssertionError("A witness changed retained evidence")
    if [source_labels[s][1] for s in pair] != [False, True]:
        raise AssertionError("Source execution does not support the opposed witness labels")
    if any(source_labels[s][0] != query["old_verdict"] for s in pair):
        raise AssertionError("An old-invalid observation was reported as a witness")


def make_guards(protocol, source_root=DEFAULT_OUT):
    spec = protocol["source"]
    return tuple(SourceGuard(source_root / "sources" / spec[version] / spec["path"], spec["class"], spec["method"])
                 for version in ("before_commit", "after_commit"))


def run(output: Path = DEFAULT_OUT, source_root: Path = DEFAULT_OUT):
    protocol, lock, _ = verified_inputs(source_root)
    output.mkdir(parents=True, exist_ok=True)
    before, after = make_guards(protocol, source_root)
    model, source_labels, executions = GuardProblem(), {}, []
    for state in STATES:
        results = (before.execute(state), after.execute(state))
        labels = tuple(r["guard_passed"] for r in results)
        if labels != tuple(model.label((), state, new) for new in (False, True)):
            raise AssertionError(f"Source/model disagreement at {state!r}")
        source_labels[state] = labels
        executions.append({"input": dict(zip(BLOCKS, state)), "before": results[0], "after": results[1],
                           "full_input_outcome_changed": labels[0] != labels[1]})
    engine = FiniteDiagnostics(model)
    audit = []
    for query in all_queries():
        result = engine.diagnose(query)
        reference = source_reference_diagnosis(query, source_labels)
        if {k: result[k] for k in ("status", "robust_masks")} != reference:
            raise AssertionError(f"Independent diagnostic disagreement: {query!r}")
        check_witnesses(query, result, source_labels)
        audit.append({"query": query, "diagnostic": result, "source_reference": reference,
                      "source_witness_check": "passed"})
    ledger = []
    for policy, mask in (("status_only", 1), ("full", 3)):
        for i, state in enumerate(STATES):
            query = {"base": (), "mask": mask, "observed": projection(state, mask), "old_verdict": source_labels[state][0]}
            result = engine.diagnose(query)
            if result["status"] == "invalid_receipt":
                raise AssertionError("Predeclared retention policy failed old sufficiency")
            # Do not feed the hidden actual state into diagnosis; use it only to
            # instantiate the checked single missing-block response afterwards.
            recovery = None
            if result["status"] == "insufficient":
                additional = result["robust_masks"][0]
                extended_mask = mask | additional
                compatible = [s for s in STATES if projection(s, extended_mask) == projection(state, extended_mask)]
                new_values = {source_labels[s][1] for s in compatible}
                if len(new_values) != 1:
                    raise AssertionError("Reported acquisition did not determine the source guard")
                recovery = {"acquired_blocks": [BLOCKS[j] for j in range(2) if additional & (1 << j)],
                            "returned_values": list(projection(state, additional)),
                            "new_guard_verdict": next(iter(new_values)),
                            "scope": "Constructed same-input completion, not ERPNext database recovery"}
            ledger.append({"constructed_id": f"{policy}-{i:02d}", "retention_policy": policy,
                           "complete_input_for_evaluation_only": dict(zip(BLOCKS, state)),
                           "query": query, "diagnostic": result, "completion_check": recovery})
    # Upstream integration assertions are not run. Replay only their selected
    # guard inputs using the unchanged before/after method, plus cancellation
    # negative control documented by the changed source itself.
    scenarios = [
        ("closed_order_return_guard", ("Closed", True), "Upstream second_return.submit and second_return.cancel guard context"),
        ("closed_order_ordinary_receipt_guard", ("Closed", False), "Upstream blocked_pr.save has the same boundary outcome; its distinct save path is not executed here"),
        ("cancelled_order_return_guard", ("Cancelled", True), "Source-preserved cancellation guard; additional negative control, not an assertion in this upstream test"),
        ("to_bill_order_return_guard", ("To Bill", True), "Upstream first return before closing the order, selected guard context"),
    ]
    scenario_rows = [{"scenario": n, "state": dict(zip(BLOCKS, s)), "before": before.execute(s)["guard_passed"],
                      "after": after.execute(s)["guard_passed"], "provenance_and_boundary": p} for n, s, p in scenarios]
    retention_summary = []
    for policy in ("status_only", "full"):
        rows = [x for x in ledger if x["retention_policy"] == policy]
        unique = {json.dumps(x["query"], sort_keys=True): x for x in rows}
        retention_summary.append({"policy": policy, "constructed_complete_inputs": len(rows),
                                  "distinct_retained_observations": len(unique),
                                  "complete_input_counts": dict(Counter(x["diagnostic"]["status"] for x in rows)),
                                  "observation_counts": dict(Counter(x["diagnostic"]["status"] for x in unique.values()))})
    summary = {
        "protocol_id": protocol["protocol_id"], "protocol_sha256": lock["sha256"],
        "script_sha256": digest(Path(__file__)), "source_manifest_sha256": digest(source_root / "source_manifest.json"),
        "finite_engine_sha256": digest(ROOT / "src/logistics_validation/focused_diagnostics.py"),
        "published_change_count": 1, "source": protocol["source"],
        "bounded_blocks": list(BLOCKS), "bounded_values": [list(STATUSES), [False, True]],
        "complete_states": len(STATES), "source_method_executions_for_state_agreement": 2 * len(STATES),
        "changed_complete_outcomes": sum(a != b for a, b in source_labels.values()),
        "source_model_disagreements": 0, "observation_queries_including_both_old_claims": len(audit),
        "all_query_status_counts": dict(Counter(r["diagnostic"]["status"] for r in audit)),
        "diagnostic_disagreements": 0, "retention": retention_summary,
        "upstream_scenario_guard_replays": scenario_rows,
        "extraction": {"before": before.metadata, "after": after.metadata},
        "limits": [
            "One convenience-selected published guard change; no representative maintenance prevalence claim.",
            "Six constructed complete states and their partial projections; no ERPNext event or historical retention logs.",
            "Selected order-status guard only. Entire save, submit, cancel, database and ledger behavior are not validated.",
            "The full upstream integration test was archived but not executed; only explicitly listed guard contexts were replayed.",
            "Sufficiency concerns reuse under the new rule, not retroactive revocation of historically valid old decisions.",
            "The existing finite diagnostic mechanism is reused through a new adapter; this is not a benchmark of the three engines or checked production recovery.",
        ],
    }
    write_jsonl(output / "source_execution.jsonl", executions)
    write_jsonl(output / "observation_audit.jsonl", audit)
    write_jsonl(output / "retention_ledger.jsonl", ledger)
    write_json(output / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--sources", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    result = run(args.output, args.sources)
    print(json.dumps({k: result[k] for k in ("complete_states", "changed_complete_outcomes", "source_model_disagreements",
                                           "observation_queries_including_both_old_claims", "diagnostic_disagreements", "retention")}, indent=2))


if __name__ == "__main__":
    main()
