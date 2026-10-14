"""Run the unmodified upstream regression in a real Frappe test site.

No method is mocked or replaced. The tracer observes Python calls, returns,
and exceptions only while the selected upstream test method runs. It reads
already materialized Document attributes without querying the database.
Run from the bench/sites directory using the bench virtualenv Python.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    target = "test_purchase_return_against_closed_purchase_order"
    observed = {
        "validate", "on_submit", "on_cancel", "update_ordered_and_reserved_qty",
        "check_for_on_hold_or_closed_status", "check_purchase_order_on_hold_or_close",
        "save", "submit", "cancel", "update_status",
    }
    active = False
    seq = 0
    handle = (args.out / f"{args.label}_trace.jsonl").open("w")

    def trace(frame, event, arg):
        nonlocal active, seq
        name = frame.f_code.co_name
        filename = frame.f_code.co_filename
        is_target = name == target and filename.endswith("test_purchase_receipt.py")
        if event == "call" and is_target:
            active = True
        selected = active and (is_target or name in observed) and "/apps/" in filename
        if selected and event in {"call", "return", "exception"}:
            obj = frame.f_locals.get("self")
            values = getattr(obj, "__dict__", {})
            doc = {
                key: values.get(key)
                for key in ["doctype", "name", "docstatus", "is_return", "return_against", "status"]
                if key in values
            }
            row = {
                "sequence": seq, "event": event,
                "file": filename.split("/apps/", 1)[1],
                "function": name, "line": frame.f_lineno, "document": doc,
            }
            if values.get("doctype") in {"Purchase Receipt", "Purchase Invoice"}:
                row["linked_purchase_orders"] = sorted({
                    item.__dict__.get("purchase_order")
                    for item in values.get("items", [])
                    if item.__dict__.get("purchase_order")
                })
            po_values = getattr(frame.f_locals.get("po_obj"), "__dict__", {})
            if po_values:
                row["guard_purchase_order"] = {
                    key: po_values.get(key)
                    for key in ["name", "status", "docstatus"] if key in po_values
                }
            if name == "check_for_on_hold_or_closed_status" and "status_map" in frame.f_locals:
                row["validation_status_map"] = dict(frame.f_locals["status_map"])
            if event == "exception":
                row["exception"] = {"type": arg[0].__name__, "message": str(arg[1])}
            handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            seq += 1
        if event == "return" and is_target:
            active = False
        return trace if selected or is_target else None

    os.environ["CI"] = "Yes"
    import frappe
    frappe.init("test_site")
    frappe.connect()
    # Same initialization as Frappe's light-mode test runner, with explicit
    # single-test selection. The pinned loader otherwise imports every installed
    # app's test modules when --test is supplied, even together with --module.
    from frappe.tests.utils import toggle_test_mode
    from frappe.utils.scheduler import disable_scheduler
    disable_scheduler()
    frappe.clear_cache()
    toggle_test_mode(True)
    from erpnext.stock.doctype.purchase_receipt.test_purchase_receipt import TestPurchaseReceipt
    suite = unittest.TestSuite([TestPurchaseReceipt(target)])
    sys.settrace(trace)
    try:
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        summary = {"label": args.label, "tests_run": result.testsRun,
                   "failures": len(result.failures), "errors": len(result.errors),
                   "skipped": len(result.skipped), "successful": result.wasSuccessful(),
                   "selected_upstream_test": target, "trace_events": seq}
        (args.out / f"{args.label}_test_result.json").write_text(json.dumps(summary, indent=2) + "\n")
        if not result.wasSuccessful():
            raise SystemExit(1)
    finally:
        sys.settrace(None)
        handle.close()


if __name__ == "__main__":
    main()
