# ERP guard provenance correction — v1.0.0

Verified on 2026-10-15. This correction applies to the research artifact tagged `v1.0.0`, commit `0b44e242d24d63f88ff7b3d50545a1583a260045`.

In `scripts/analyze_public_procurement_change.py`, the `to_bill_order_return_guard` scenario uses the constructed input `(purchase_order.status="To Bill", is_return=true)`. Its description, also saved in `results/beta_improvement_20261012/public_change/summary.json`, incorrectly connects this exact input to the upstream test's first return before the order is closed.

The actual purchase-order status observed at that first return's stock-update guard is **`To Receive and Bill`**. The original traces record it at sequence 151 in `results/final_v1_refinement_20261012/erp_clean_replay/before_trace.jsonl` and sequence 155 in the corresponding `after_trace.jsonl`. Both rows record `is_return=1` and `guard_purchase_order.status="To Receive and Bill"`.

Read the scenario description as follows:

> Constructed open-order return control using To Bill. The upstream first return was observed with purchase-order status To Receive and Bill; it is a different input that takes the same branch in the selected guard.

Both statuses pass the selected guard before and after the fix because neither is `Closed` nor `Cancelled`. The six modeled inputs, 24 partial-observation/old-Boolean queries, reported diagnostic counts, and conclusions are unchanged. This correction does not add an observed state to the six-input model or establish an actual historical partial receipt. The manuscript already distinguishes the isolated guard from the application regression and does not claim that every modeled state is reached there.

The original source, saved outputs, trace files, manifests and `v1.0.0` tag are preserved for reproducibility. This addendum corrects the provenance description associated with that archived generator and its outputs. No ERP service was rerun and no new experimental outcome is claimed. When interpreting or regenerating the archived result, apply the description above.
