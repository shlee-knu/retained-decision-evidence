# Receipt revalidation: fixed design and evidence

Design recorded 2026-10-08 before implementing or executing this addition. Existing files and results are preserved. This is a controlled replay of public data and authored observation contracts, not a source organization's deployment or policy history.

## Fixed design

The executable takes before/after catalogs and explicit versioned completion domains, plus a receipt containing the full repeated activity projection, only previously read P/T values, and a Boolean recorded verdict. The receipt binds the old catalog, old domain and an immutable source snapshot. A matching hash is a consistency condition, not authentication of source values or validation of an unread upstream guarantee.

The supported domains are Cartesian, nondecreasing first clocks along first-occurrence order, Consignment excluding invoice/clear, and the intersection. They use the existing four-profile/four-activity quotient and exact arbitrary-precision clock comparisons. Later repetitions are preserved in concrete witnesses but are irrelevant to these predicates.

The old compatible fiber must be nonempty and contain only the recorded verdict. Otherwise the receipt is invalid. The new fiber is classified as unsupported when empty, safe when all labels equal the recorded verdict, stale_verdict when all labels equal the opposite verdict, and insufficient when both labels occur. Safe remains conditional on truthful retained values and actual membership in the asserted new domain; the tool never infers hidden-domain membership from a nonempty fiber. Concrete completions preserve every observed value and literal timestamp and identify whether they also belong to the old domain.

Constructed examples cover guarantee withdrawal with an unchanged catalog, globally equivalent catalogs, a changed full label with unchanged sufficiency, narrowing that excludes a fully observed state, invalid old receipts and explicit syntax/domain boundaries. No performance claim or new timing matrix is planned.

Native replay uses all 50,931 original salt-17 test cases and the preserved baseline structural masks. It reconstructs old receipts from the pinned source snapshot, revalidates baseline-to-strict under the Cartesian domain, and requests missing blocks only after an insufficient outcome. Recovery counts are logical block reads from a recorded in-memory accessor, not SQL calls or a network measurement. The independent raw occurrence/Fraction oracle checks both original and recovered verdicts. Every old receipt and issued recovery read is retained in a compressed audit stream.

**Known expectation before this run:** existing inspected counts imply 33,489 old T-only receipts need P, while 5,605 old P receipts become nonminimal but remain valid. Retained-observation recovery therefore does not subtract the latter sunk reads; the earlier fresh-request increase remains 27,884. This is a prespecified reconciliation expectation from known evidence, not a new held-out discovery. The replay must compute it rather than copying counts.

## Execution evidence

The focused suite passes **56 tests** with no failures or errors. Thirteen executable examples produce their declared classifications. The full native replay processes the pinned 251,734 source rows and all 50,931 original test cases. Independent raw occurrence/Fraction references check 101,862 original/recovered verdicts with zero disagreements. These are implementation/replay checks, not natural-error labels or additional independent source cases.

| Native retained-observation result | Cases or reads |
|---|---:|
| Old receipts conditionally safe under the new catalog | 17,442 |
| Old receipts insufficient under the new catalog | 33,489 |
| Additional P reads during recovery | 33,489 |
| Additional T reads during recovery | 0 |
| Safe old receipts with newly redundant observations | 5,605 |
| Stale-verdict, unsupported or invalid native receipts | 0 |
| Recovered passing verdicts | 39,142 |
| Recovered failing verdicts | 11,789 |

The additional reads return 1,471,664 bytes under the preserved block encoding. The original retained observations contain 52,855 logical reads and 6,705,042 bytes. Retaining them and adding recovery reads therefore totals **86,344 logical reads and 8,176,706 bytes**. Fresh strict execution uses **80,739 logical reads and 7,930,384 bytes**. The difference is 5,605 already acquired P observations, or 246,322 bytes, that a fresh execution can avoid. No past acquisition cost is refunded in the retained-observation ledger. These independently replayed counts match the expectation declared before this run.

The recovery policy validates the original receipt once, then reads missing P before missing T only while the new-domain fiber remains ambiguous. It evaluates accumulating observations against the **new** domain. A newly read reversed clock after withdrawal of chronology can violate the old guarantee while still being supported by the new domain; the recovery result reports this old-domain incompatibility instead of retroactively treating the new value as part of the historical receipt. An explicit regression checks this boundary. The fixed read order is a concrete recovery policy, not a globally minimum recovery algorithm. In the native insufficient cases, P is the sole missing block and is necessary, so exactly one P read repairs each certificate.

The constructed cases include an unchanged catalog with each guarantee withdrawn, an empty-observation withdrawal of both guarantees, a globally equivalent catalog with unchanged certificates, a full observation whose changed contract flips the cached verdict while remaining sufficient, and a new domain that excludes a complete observation. Invalid old receipts cover empty fibers, ambiguous fibers and incorrect recorded labels. An equivalent-catalog control is independently checked on all 8,612 complete quotient classes. Sixteen before/after domain pairs are checked on three representative activity/profile shapes and all four observation masks against explicitly filtered raw completions. Literal timestamps, offsets, subnanosecond ordering, repeated events, binding errors, hidden-read avoidance and CLI overwrite refusal are also checked.

No live SQL recovery is claimed. `read_block` is an instrumented in-memory accessor whose issued logical reads are compared with the returned recovery ledger. No added network latency, new timing matrix or retrained plan is used. The source snapshot is fixed and its hash checked; receipt hashes do not establish authenticity, freshness of a live system or validity of unread upstream guarantees.

## Reproduction and artifacts

Run at the repository root. Use a new output directory for a reproduction, preserving the delivered results:

```sh
.venv/bin/python -m pytest tests/test_receipt_revalidation.py -q --junitxml results/reproduced/receipt_revalidation/pytest.xml
.venv/bin/python scripts/revalidate_receipt.py --suite --output results/reproduced/receipt_revalidation
```

The suite permits an output directory containing only the focused pytest records and refuses to overwrite existing evidence. The canonical run used `results/second/receipt_revalidation/` instead. A single receipt can be checked without any complete workload or hidden metadata:

```sh
.venv/bin/python scripts/revalidate_receipt.py --receipt examples/second_receipt_withdrawal.json --before examples/baseline_catalog.json --after examples/baseline_catalog.json --before-domain chronological:v1 --after-domain cartesian:v1 --snapshot-sha256 0000000000000000000000000000000000000000000000000000000000000000 --output results/reproduced/receipt_withdrawal.json
```

The all-zero snapshot digest is explicitly a constructed fixture identifier, not an actual public-source hash. The command returns `insufficient`, with accepting/rejecting completions that share the supplied observation and retain its entire repeated activity sequence. A completion admitted only after guarantee withdrawal is explicitly marked outside the old domain.

`examples/second_receipt_cases.json` contains all 13 input receipts and expected outcomes. `examples/second_equivalent_catalog.json` adds a redundant transitive edge; `examples/second_label_flip_catalog.json` requires an additional Consignment milestone, without making the profile globally unsatisfiable. `examples.json` retains all classifications and concrete witnesses. `native_summary.json` contains the aggregate ledgers and representative native receipts. `native_receipts.jsonl.gz` retains every reconstructed old receipt, initial classification, issued additional reads and recovered verdict in deterministic source order. It is 624,243 bytes and has SHA-256 `d08fbc83a4ef278e750f200f0cd30c0c8683b86cda93ac544fecdb1bfec1ead0`.

`manifest.json` hashes all input source, implementation, example and test files, plus the generated examples, native summary, compressed receipts and focused pytest XML. Its `design_prefix_sha256` binds the unchanged pre-execution portion of this document before the Execution evidence heading, allowing the actual results to be appended without invalidating that design record. The source compact and archived mask hashes remain `3fdfe926a29d35c87a2652447df420bb5c726ab2c996f6317c830d75cc4a1b3b` and `0060fe4c8015fa6d7c49da8661acaf073bb28ef6f0dcd1fc9ca4f6b88fa336b6`.
