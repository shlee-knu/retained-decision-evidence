# Retained decision evidence under rule changes

Research code and selected scientific evidence for **Change-Impact Analysis of Retained Decision Evidence in Manufacturing Procurement**, prepared for IEEE Access. The procedure checks whether observations retained for an earlier decision remain sufficient under a changed rule, explains ambiguity with compatible inputs, and checks replacement records.

This repository contains the implementation, tests, research contracts, permitted BPI Challenge 2019 derivatives, synthetic fixtures, and selected saved measurements. The contracts and retention policies are constructed for the study. The evaluated archive is one public procurement dataset; repeated partitions, rule variants and timing rounds are not independent organizations or deployment studies.

## Provenance correction

[ERRATA.md](ERRATA.md) corrects one description that associated the constructed `To Bill` return control with an upstream execution whose actual order status was `To Receive and Bill`. The original scientific source and saved results are preserved; diagnostic counts and manuscript conclusions are unchanged. The paper-pinned `v1.0.0` remains immutable. Version `v1.0.1` adds this documentation-only correction.

## Reproduce the core evidence

Run from the repository root with Python 3.11 or later. Python 3.12.3 was used for the clean checks. Every invocation needs a new output directory.

```bash
python3 scripts/reproduce_current.py --scope evidence --output results/my_evidence_replay
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-current.txt
.venv/bin/python scripts/reproduce_current.py --scope audit --output results/my_audit_replay
```

The standard-library `evidence` scope verifies 167 saved-evidence checks, independently recomputes 834,880 target/observation comparisons, reconciles 50,931 reconstructed records and the 33,489 affected IDs, and semantically verifies the portable report bundle. The `audit` scope adds the selected implementation regression tests. The staged repository passed both scopes, including **297 tests**. These checks use included derivatives; they do not reparse the original XES or remeasure performance.

An optional actual OPA replay requires the official pinned Linux x86_64 executable. It is excluded from this repository; download and verify it before selecting the platform scope:

```bash
.venv/bin/python scripts/fetch_opa_dependency.py
.venv/bin/python scripts/reproduce_current.py --scope platform --output results/my_platform_replay
```

The downloader verifies OPA 1.21.1 against SHA-256 `668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031`. This optional scope starts a loopback OPA server and reruns the adapter. Core evidence verification checks the saved OPA output, not a fresh OPA execution.

## Scientific result map

The table and figure numbers refer to the accompanying study. Saved timing results describe their recorded host and measurement boundaries; recomputing summaries does not reproduce those elapsed times.

| Study result | Included scientific evidence | Entry point |
| --- | --- | --- |
| Table 4: retention sensitivity | `results/robustness_revision_20261011/retention/run_final/` | `scripts/analyze_retention_robustness.py --output NEW_DIRECTORY` |
| Table 5: target census and filtering | `results/compact_revision/evidence/`; `results/robustness_revision_20261011/census/run/` | `scripts/analyze_census_robustness.py --output NEW_DIRECTORY` |
| Figure 2: changes versus acquisition needs | `results/beta_improvement_20261012/native_projection/run/`; `results/access_practical_revision_20261012/impact/` | `scripts/analyze_native_change_projection.py --output NEW_DIRECTORY`; `scripts/draw_native_change_impact.py --output NEW_DIRECTORY --figures NEW_FIGURE_DIRECTORY` |
| Table 6: diagnostic timing rounds | `results/perspective_revision/diagnostics/`; `results/focused_revision/diagnostics/` | `scripts/benchmark_revision_diagnostics.py prepare --output NEW_INPUT_DIRECTORY`, then `run --inputs NEW_INPUT_DIRECTORY --output NEW_RUN_DIRECTORY` |
| Table 7: complete paired workflows | `results/access_practical_revision_20261012/workflow/paired/` with scaling/profile controls | `scripts/benchmark_equal_workflow.py --mode paired --output NEW_DIRECTORY` |
| Table 8: SQLite replacement generation | `results/third/sqlite_migration/` | `scripts/benchmark_receipt_migration.py --stage prepare --output NEW_DIRECTORY --source-db REBUILT_SOURCE_DB`, then `--stage benchmark --output NEW_DIRECTORY` |
| Checked recovery and portable reports | `results/repair_revision_20261010/execution/`; `results/alpha_revision_20261010/audit_report/run/` | `scripts/run_receipt_repair.py`; `scripts/export_audit_report.py` |
| Published ERPNext guard change | `results/beta_improvement_20261012/public_change/` | `scripts/analyze_public_procurement_change.py --output NEW_DIRECTORY` |
| ERPNext full application regression | `results/access_practical_revision_20261012/erp_integration/`; `results/final_v1_refinement_20261012/erp_clean_replay/` | Recorded traces and results; optional isolated Docker replay described below |
| Selected FHIR/EPCIS predicates | `results/standards_extension/`; `data/external/*/manifest.json` | `scripts/acquire_fhir_standards.py`, `scripts/acquire_epcis_extension.py`, and corresponding validation scripts |

Use the Python interpreter from the environment and `--help` for each entry point. Optional scripts that import project modules directly need `PYTHONPATH=src:scripts`. Plotting needs the additional pinned packages in `requirements-practical.txt`. The SQLite source database can be rebuilt from the included BPI compact data with `scripts/benchmark_sqlite_integration.py --stage prepare --output NEW_SOURCE_DIRECTORY`; databases are not shipped. CPU-affinity and timing assumptions are specified in the corresponding `configs/*protocol.json` files. Fresh measurements belong in separate output directories.

For a read-only check of the saved ERP replay:

```bash
python3 results/final_v1_refinement_20261012/erp_clean_replay/verify_clean_replay.py \
  --original results/access_practical_revision_20261012/erp_integration
```

The ERP stub experiment and full application regression establish different scopes. Reinstalling the full regression requires Git, Docker, network downloads, and the pinned dependency files. The included `reproduce.py` in the ERP replay directory accepts new `--workdir` and `--output` destinations. Installed ERP services and SQL snapshots are excluded.

FHIR and EPCIS originals, validators and installed Node packages are excluded. Their acquisition scripts and manifests identify the required official versions and hashes; external validation needs those downloads and additional Java/Node/Python dependencies. Saved synthetic results can be inspected without them. The small core audit environment is not the complete environment for every optional experiment. The external traffic/travel acquisition controls likewise require separate retrieval under their original terms; the included control outputs are aggregate summaries only.

## Data and licensing

Project-authored code is **AGPL-3.0-only**, as specified in [LICENSE](LICENSE). Third-party materials retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

**Case-level BPI Challenge 2019 derivatives are included.** These include compact milestone/profile/time records, reconstructed receipts, affected-ID indexes, acquisition/recovery ledgers, and persisted workflow payloads. They retain the source's CC BY 4.0 attribution requirement. Source: Boudewijn van Dongen (2019), *BPI Challenge 2019*, 4TU.ResearchData, [doi:10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1](https://doi.org/10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The project selects four purchasing milestones, preserves first timestamps and profiles, and derives research receipts, diagnoses and indexes. These are transformed research artifacts, not the original enterprise log or independently adjudicated error labels. Original deposit and acquisition metadata are in `data/provenance/`.

Raw XES archives, record-level traffic/travel derivatives, original standards and academic PDFs, manuscript and cover-letter files, author metadata, internal review narratives, application installations, and the old Git history are excluded. Traffic source metadata records noncommercial General Terms; travel metadata records CC BY-NC 4.0. Their inclusion as citations or aggregate statistics does not relicense the original records.

## Preserved provenance paths

Scientific files retain their recorded bytes and hashes. Some saved JSON/log metadata contains the original machine's absolute paths or public upstream contributor names. Those paths describe an earlier execution; the core runner resolves artifacts inside this checkout and does not depend on that home directory. They are not credentials or live source endpoints. The ERP replay uses the synthetic local test constants `access-local-test` and `access-local-admin`, and upstream CI includes a `root` database test default; these identify isolated test setup values, not deployed services.

One exact historical source file is retained at `paper/history/ICSE_NIER_2026_ALPHA/source_code/src/logistics_validation/audit_report.py` because the saved OPA manifests pin that version. No manuscript is stored there. The historical directory/tag name is provenance; the current study target is IEEE Access. Three independent scientific checker files remain under `results/panel_review_20261009/` because the compact evidence manifest hashes them; review narratives from that directory are excluded. The independent repair checker at `results/repair_revision_20261010/methods/check_repair_methods.py` is also retained because the complete-workflow manifest hashes it.

`PUBLIC_RELEASE_MANIFEST.json` lists the public files and SHA-256 digests. Reproduction outputs and local environments should remain separate from the preserved evidence.
