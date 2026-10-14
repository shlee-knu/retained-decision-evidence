# Actual SQLite integration experiment: fixed design

Design fixed on 2026-10-07, before implementation or timing. The parent approved SQLite only: two storage layouts, the complete 50,931-case salt-17 procurement test workload, two catalogs, five implementations, two warmup rounds and seven measured rounds. Existing manuscripts, source engines and evidence remain unchanged. All new outputs belong under `results/strong/sqlite_integration/`.

## Question and evidential boundary

Does selective metadata acquisition improve the measured cost of an actual embedded database validator, after comparing it with one joined fetch and with an ordinary activity guard followed by a joined fetch? Does the observed answer change when metadata occupy one row rather than two normalized tables?

This is a controlled, single-host, read-only SQLite integration experiment on public procurement data. It will measure real SQL execution, copying returned values, JSON decoding and contract evaluation. It is a warm-cache host experiment, not a production deployment, network benchmark, disk-cold workload, concurrent-update evaluation, or proof of economic value. No sleep, artificial network delay, payload padding, data duplication, fake faults or favorable-result selection will be used. Null or adverse results are retained.

## Source and preparation

Use the frozen `results/v03/bpi_compact.jsonl.gz` containing all 251,734 public BPI2019 cases. Build each database from **all** cases, then evaluate exactly the existing salt-17 test cases selected by purchasing-document hash. This retains a complete source relation rather than creating a conveniently tiny test-only database. The canonical source hash, selected-ID digest and legacy engine hash must match the previous experiment.

The input is the existing compact derivative. Original XES download, parsing and projection are not rerun or charged as part of database preparation. Record this limitation explicitly. Measure the compact-file parsing, block serialization, database insertion/commit, integrity checks and complete preparation wall/CPU times separately where attribution is possible. Oracle calculation is verification work and is separately identified. Record source and database sizes, page counts, page size, table row counts, logical serialized metadata bytes, and preparation memory high-water marks. Do not call serialized-byte reduction a reduction in physical page IO.

Metadata blobs retain the exact previous compact sorted-key UTF-8 JSON encoding. The policy receives only the case identifier and already available complete activity projection. Positions, structural eligibility, clock parsing and query-order selection are recomputed during the decision. No profile, timestamps, label, eligibility flag, stored verdict or precomputed first-position map is attached to that base input. Independent truth vectors are held by the experiment controller and compared with returned outcome vectors outside the timed decision loop. Metadata byte buffers used for database construction are released before timing.

## Storage layouts and SQL boundaries

Both layouts use the actual case identifier as a text primary key and SQLite `WITHOUT ROWID` tables. Both store the same bytes with no redundant decision columns.

| Layout | Tables | Joined full fetch |
| --- | --- | --- |
| Same row | metadata(case_id, profile_blob, time_blob) | One indexed SELECT returning both columns |
| Normalized | profiles(case_id, payload), timestamps(case_id, payload) | One indexed SELECT joining the two tables by case_id |

A profile-only or time-only accessor performs a parameterized indexed SELECT of that block. A joined fetch returns both blobs in one SQL statement; both are decoded and charged as two logical field values but one SQL request. Separate full retrieval performs two real SQL statements. No SQL query computes or caches the contract verdict. SQLite may read an entire underlying page even when a query returns one column; application payload accounting does not establish storage IO savings.

Use ordinary read-only connections, no concurrent writers, and a consistent static snapshot for the entire experiment. Record the SQLite/Python versions, compile options, query plans, journal mode, page size, cache setting and connection statement-cache setting. Explicitly disable memory-mapped access and use a declared 128 MiB suggested SQLite page cache per connection. The operating-system cache is not flushed. Priming and the two full warmup rounds make this a warm-cache comparison; no claim of measured cache-hit probability is made.

The official SQLite documentation defines `cache_size` as a suggested page-cache limit and `EXPLAIN QUERY PLAN` as a diagnostic of query access strategy. Record the actual settings and indexed point-lookup plans rather than inferring physical reads from logical query counts. Sources: [SQLite PRAGMA documentation](https://www.sqlite.org/pragma.html#pragma_cache_size), [EXPLAIN QUERY PLAN](https://www.sqlite.org/eqp.html), and [Python 3.12 sqlite3 documentation](https://docs.python.org/3.12/library/sqlite3.html).

## Five implementations

| Implementation | Work included |
| --- | --- |
| joined_full | Fetch both blobs in one SQL statement, decode both, evaluate the actual profile once |
| separate_full | Fetch and decode each block in a separate SQL statement, evaluate the actual profile once |
| guard_joined | Compute ordinary base structural eligibility; reject without metadata if every profile is impossible; otherwise fetch both in one SQL statement and evaluate once, reusing the computed eligibility |
| hand_selective | Existing explicit structural short-circuit implementation, with each requested block backed by an actual SQL query |
| generic_selective | Existing structural selector and certificate-producing acquisition engine, with each requested block backed by an actual SQL query |

The first three prevent the baseline from being inflated by repeated certificate construction or unnecessarily separate requests. The guarded joined baseline is especially important: skipping a case whose activity projection already determines rejection is an ordinary optimization, not evidence for a novel optimizer. The hand and generic selective implementations must retain identical read masks on supported inputs. Rich certificate objects and visible-input validation remain additional output/service work in the generic implementation; its runtime is not an intrinsic cost lower bound for every certificate implementation.

Reused functions will be imported from the frozen acquisition module and previous fair benchmark without modifying either. The new accessor contains only database connection, case identifier, activity tuple, and per-decision caches/ledger. Each fetched blob is JSON-decoded once; a joined fetch legitimately populates both block caches. Reuse within a decision is allowed; no cross-case decoded-value or verdict cache is allowed.

## Accounting, correctness, and counterexamples

Record logical P/T values returned, compact payload bytes, SQL statement count, returned SQL rows, JSON decodes, zero/one/two logical-block cases and accepted/rejected counts. These counters distinguish one joined SQL request from two field values. Record CPU and wall clocks around identical complete-workload loops, including accessor allocation, SQL, decoding, predicates, certificate production where applicable, common outcome-vector construction and ledger aggregation. Compare truth after the timer. Record process-level page faults and block-input counters as coarse environmental diagnostics, not per-statement physical IO measurements.

Before timing, verify both full database relations against an order-independent digest of their source case identifiers and exact P/T blobs, using row counts, primary-key uniqueness, an integrity check and source-derived row hashes. Independently compute complete-input truth using the existing separate Fraction oracle, then evaluate all five methods on both catalogs and layouts. This yields 1,018,620 native method-case comparisons. Match original P/T and byte totals for separate-full and both selective methods. Reconcile guarded-joined counts with the base-decisive cases in the frozen access traces. Every warmup and measured run must reproduce its verified ledger and outcome vector.

Focused tests will check: an eager joined baseline really performs one SQL statement and decodes both fields even on a base-decisive case; separate-full really performs two statements; the guard skips both fields; normalized and same-row layouts preserve identical metadata values/verdicts; query plans use primary-key searches; equal instants with different offsets, sub-microsecond clock reversal, missing/repeated milestones and strict forbidden consignment activities match the independent oracle. Poisoned or absent hidden rows can prove that a guard does not access them, but cannot extend correctness to malformed inputs outside the trusted domain. No natural-anomaly labels are introduced.

The integration retains the original catalog regression as a matched native counterexample. Selective SQL calls are expected to be 52,855 under the permissive catalog and 80,739 under strict consignment, despite equal complete-input labels. Joined-full uses 50,931 statements; guarded-joined should use 47,202 and 41,597. These are pre-existing logical predictions to be checked against actual database calls, not newly measured timings or promises that one method will be faster.

## Timing schedule and scope

The fixed main matrix is 2 layouts × 2 catalogs × 5 methods × (2 warmup + 7 measured rounds), or 180 complete-workload runs: 40 warmup and 140 measured rows. Each run processes all 50,931 cases, for 9,167,580 timed/warmup case evaluations. A fixed seed shuffles the same case-index order for every method in a round and randomizes all 20 layout/catalog/method jobs within that round. Use the same connections and declared caches across methods; first-query statement preparation is absorbed by the complete warmups. Keep normal garbage collection enabled and collect only outside each timed job.

Pin the single benchmark process to one allowed CPU if available, record affinity, and coordinate a quiet timing slot with other agents. This matrix uses one synchronous reader; it does not estimate multi-client throughput, tail latency under queueing, reader/writer contention or network concurrency. A new concurrent workload would require its own fair scheduling and snapshot protocol, and is outside this approved experiment.

Report per-round values, median and empirical interquartile range, paired per-round CPU/wall differences against joined-full and guarded-joined, cases per second, actual SQL counts, and actual output bytes. Do not treat repeated rounds on one host as independent enterprise samples or manufacture confidence in transport latency. Compare methods within each layout/catalog. Preparation costs and database sizes are reported alongside the conditional decision component; any total adoption discussion must also mention the omitted original-XES-to-compact conversion.

Before requesting the timed slot, complete source/storage/native correctness checks and provide an untimed preparation report. A small new calibration output may estimate runtime, but it is not the main result and must not replace or silently reduce the fixed main workload. Based on the previous 27–84 microsecond decision costs and about nine million case evaluations, initial expected timing is roughly 8–20 minutes plus preparation/verification; this is an estimate, not a measurement. Report a materially larger estimate before starting. Do not stop early because a result is unfavorable. No iteration to select a faster policy after seeing measured comparisons is planned.

## New artifacts

The approved implementation is `scripts/benchmark_sqlite_integration.py`, with focused tests in `tests/test_sqlite_integration.py`. Preparation, database manifests, correctness results, query plans, raw rounds and summaries go to `results/strong/sqlite_integration/`. The two generated databases are public-data derivatives under the source terms and are not automatically redistributed. A later `docs/strong_integration_evidence.md` will describe actual outcomes and limits. The original 106-file verified set is not modified; new-phase verification must be separate.
