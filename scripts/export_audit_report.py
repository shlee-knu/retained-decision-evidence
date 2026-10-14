"""Export/verify a small portable audit bundle and exact strict-change ID index."""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from logistics_validation.audit_report import (
    canonical, catalog_from_content, digest, file_digest, make_bundle, receipt_query,
    require, verify_bundle,
)
from logistics_validation.focused_diagnostics import Problem


def load(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def export(output):
    require(not output.exists(), "output directory already exists")
    source_paths = set()

    def saved(path):
        source_paths.add(path)
        return load(ROOT / path)

    def inputs(name):
        value = saved(f"results/focused_revision/diagnostic_inputs/{name}.json")
        results = saved(f"results/focused_revision/diagnostics/r0_{name}_unique_finite_fibers.json")["diagnostics"]
        catalog = catalog_from_content(saved(value["target"])) if value["target"] else None
        return value, results, Problem(name, catalog)

    strict, strict_results, strict_problem = inputs("procurement_strict")
    label, label_results, label_problem = inputs("procurement_label_change")
    epcis, epcis_results, epcis_problem = inputs("epcis_object_profile")
    source_paths.add("examples/baseline_catalog.json")
    protocol = saved("configs/focused_diagnostic_protocol.json")
    source_paths.add(protocol["receipt_source"])
    require(file_digest(ROOT / protocol["receipt_source"]) == protocol["receipt_source_sha256"], "native archive pin mismatch")
    snapshot_source = "results/v03/bpi_compact.jsonl.gz"
    source_paths.add(snapshot_source)
    snapshot_digest = file_digest(ROOT / snapshot_source)
    require(all(r["snapshot_sha256"] == snapshot_digest for r in strict["exemplars"]), "native snapshot source mismatch")
    weights = Counter(index for _, index in strict["weighted_requests"])
    status_counts = Counter()
    specs, affected, ids = [], [], []
    for index, (query, receipt) in enumerate(zip(strict["queries"], strict["exemplars"])):
        result = strict_results[str(index)]
        status_counts[result["status"]] += weights[index]
        request_id = "strict:" + receipt["receipt_id"]
        spec = {"problem": strict_problem, "query": query, "receipt": receipt,
                "request_id": request_id, "diagnostic": result,
                "old_identity": "examples/baseline_catalog.json", "new_identity": strict["target"]}
        specs.append(spec)
        if result["status"] == "insufficient":
            affected.append({"class_index": index, "count": weights[index], "representative_request_id": request_id,
                             "required_additional_blocks": ["profile"],
                             "reason": "Strict Consignment exclusion separates old-compatible profiles; retained T is insufficient."})
            specs.append({**{k: v for k, v in spec.items() if k != "diagnostic"},
                          "request_id": "guarantee-control:" + receipt["receipt_id"],
                          "new_domain": "consignment_exclusion:v1"})
    require(status_counts == {"safe": 17442, "insufficient": 33489} and len(affected) == 3, "strict published counts differ")
    affected_indices = {r["class_index"] for r in affected}
    for receipt_id, class_index in strict["weighted_requests"]:
        if class_index in affected_indices:
            ids.append({"receipt_id": receipt_id, "class_index": class_index, "obligation": "acquire profile"})
    require(len(ids) == 33489 and len({r["receipt_id"] for r in ids}) == len(ids), "affected ID union")
    stale_index = next(int(k) for k, v in label_results.items() if v["status"] == "stale_verdict")
    stale_receipt = label["exemplars"][stale_index]
    stale_request = "label-change:" + stale_receipt["receipt_id"]
    specs.append({"problem": label_problem, "query": label["queries"][stale_index], "receipt": stale_receipt,
                  "request_id": stale_request, "diagnostic": label_results[str(stale_index)],
                  "old_identity": "examples/baseline_catalog.json", "new_identity": label["target"]})
    specs.append({"problem": epcis_problem, "query": epcis["queries"][0], "diagnostic": epcis_results["0"],
                  "request_id": "synthetic:epcis-object:observation-0", "receipt_id": "synthetic:epcis-object:observation-0",
                  "snapshot_sha256": digest({"fixture": "epcis_object_profile", "epoch": "mock-snapshot-1"}),
                  "old_identity": "epcis_object_profile:compatible-selected:v1",
                  "new_identity": "epcis_object_profile:compliant-selected:v1"})
    provenance = {"source_artifacts": {p: file_digest(ROOT / p) for p in sorted(source_paths)},
                  "native_receipts": 50931, "strict_status_counts": dict(status_counts),
                  "affected_id_index_content_sha256": digest(ids),
                  "snapshot_source": {"path": snapshot_source, "sha256": snapshot_digest},
                  "representative_reports": "One per 20 stored native observation classes; additional controls are separate requests.",
                  "synthetic": "EPCIS and adapter assertions are authored fixtures, not live source reads."}
    bundle = make_bundle(specs, provenance)
    reports = {r["request_id"]: r for r in bundle["reports"]}
    for row in affected:
        report = reports[row["representative_request_id"]]
        require(report["robust_additional_sets"] == [["profile"]], "strict P obligation")
        control = reports["guarantee-control:" + report["receipt_id"]]
        require(control["status"] == "safe" and control["robust_additional_sets"] == [[]], "guarantee control")
        row["guarantee_control_request_id"] = control["request_id"]
    require(reports[stale_request]["robust_additional_sets"] == [[]], "stale receipt needs update, no read")
    output.mkdir(parents=True)
    # Stable gzip metadata, exact IDs once, no 50,931 duplicated report payloads.
    with (output / "affected_receipt_ids.jsonl.gz").open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
            for row in ids:
                stream.write(canonical(row) + b"\n")
    review = {"schema_version": 1, "kind": "synthetic change-owner decision record using public receipts",
              "bundle_sha256": bundle["bundle_sha256"], "native_receipts": 50931,
              "strict_status_counts": dict(status_counts), "affected_classes": affected,
              "affected_id_index": {"path": "affected_receipt_ids.jsonl.gz", "sha256": file_digest(output / "affected_receipt_ids.jsonl.gz"),
                                    "count": len(ids), "unique_ids": len(ids)},
              "exact_mapping_source": {"path": "results/focused_revision/diagnostic_inputs/procurement_strict.json",
                                       "sha256": provenance["source_artifacts"]["results/focused_revision/diagnostic_inputs/procurement_strict.json"],
                                       "fields": ["queries", "weighted_requests", "exemplars"]},
              "actions": [
                  {"owner": "rule author", "action": "review three affected observation classes and their opposed raw witnesses",
                   "basis": "affected_classes representative_request_id refers to portable reports"},
                  {"owner": "evidence custodian", "action": "retain 17,442 safe attestations; acquire P for the 33,489 indexed receipts before issuing a new strict verdict",
                   "basis": "all minimal robust sets for every affected class equal [profile]"},
                  {"owner": "execution owner", "action": "use the previously measured fresh guarded SQLite path for execution; preserve these reports as offline audit evidence",
                   "basis": "No new runtime claim: existing comparison reports fresh guarded execution faster in the measured SQLite setting."},
                  {"owner": "evidence custodian", "action": "update the retained verdict for the label-change example without acquiring a block",
                   "basis": {"request_id": stale_request, "status": "stale_verdict", "robust_additional_sets": [[]]}}],
              "guarantee_control": "With an applicable snapshot-level Consignment exclusion attestation, all three strict classes become safe with the empty additional set. This is conditional admission, not proof of hidden actual profile membership.",
              "boundary": "Authored stakeholder rules; no measured human decision speed/accuracy, live deployment, or new performance improvement."}
    # Bind sidecars into the independently retainable bundle digest. Exclude the
    # review's backlink when hashing, avoiding a circular content-address.
    bundle["provenance"]["change_review_content_sha256"] = digest({k: v for k, v in review.items() if k != "bundle_sha256"})
    bundle["bundle_sha256"] = digest({k: v for k, v in bundle.items() if k != "bundle_sha256"})
    review["bundle_sha256"] = bundle["bundle_sha256"]
    verification = verify_bundle(bundle)
    write(output / "bundle.json", bundle)
    write(output / "change_review.json", review)
    write(output / "verification.json", verification)
    manifest = {"schema_version": 1, "bundle_sha256": bundle["bundle_sha256"],
                "files": {p.name: file_digest(p) for p in sorted(output.iterdir())},
                "source_artifacts": provenance["source_artifacts"]}
    write(output / "manifest.json", manifest)
    return verify_directory(output, verify_sources=True)


def verify_sidecar_bindings(bundle, review, ids):
    require(review["bundle_sha256"] == bundle["bundle_sha256"], "review/bundle mix")
    require(bundle["provenance"]["change_review_content_sha256"] ==
            digest({k: v for k, v in review.items() if k != "bundle_sha256"}), "review content binding mismatch")
    require(digest(ids) == bundle["provenance"]["affected_id_index_content_sha256"], "affected ID content binding mismatch")


def verify_directory(folder, verify_sources=False, expected_sha256=None):
    manifest, bundle, review = (load(folder / name) for name in ("manifest.json", "bundle.json", "change_review.json"))
    for path, expected in manifest["files"].items():
        require(Path(path).name == path and file_digest(folder / path) == expected, "manifest file mismatch")
    result = verify_bundle(bundle, expected_sha256=expected_sha256 or manifest["bundle_sha256"])
    require(manifest["source_artifacts"] == bundle["provenance"]["source_artifacts"], "source manifest binding mismatch")
    with gzip.open(folder / review["affected_id_index"]["path"], "rt") as stream:
        ids = [json.loads(line) for line in stream]
    verify_sidecar_bindings(bundle, review, ids)
    require(len(ids) == 33489 and len({r["receipt_id"] for r in ids}) == 33489, "affected ID count/uniqueness")
    counts = Counter(r["class_index"] for r in ids)
    require(counts == {r["class_index"]: r["count"] for r in review["affected_classes"]}, "affected class counts")
    reports = {r["request_id"]: r for r in bundle["reports"]}
    for item in review["affected_classes"]:
        report = reports[item["representative_request_id"]]
        control = reports[item["guarantee_control_request_id"]]
        require(report["status"] == "insufficient" and report["robust_additional_sets"] == [["profile"]], "review obligation")
        require(control["status"] == "safe" and control["robust_additional_sets"] == [[]], "review control")
    if verify_sources:
        for path, expected in manifest["source_artifacts"].items():
            require(file_digest(ROOT / path) == expected, "original source changed: " + path)
        prepared = load(ROOT / review["exact_mapping_source"]["path"])
        lookup = {receipt_id: index for receipt_id, index in prepared["weighted_requests"]}
        expected_ids = {(rid, index) for rid, index in lookup.items() if index in counts}
        require({(r["receipt_id"], r["class_index"]) for r in ids} == expected_ids, "affected source mapping")
        # Compare every native ID and normalized query, without running diagnostics.
        source = load(ROOT / "configs/focused_diagnostic_protocol.json")["receipt_source"]
        seen = set()
        with gzip.open(ROOT / source, "rt") as stream:
            for line in stream:
                receipt = json.loads(line)["receipt"]
                rid = receipt["receipt_id"]
                require(rid in lookup and rid not in seen, "native ID mapping")
                seen.add(rid)
                require(receipt["snapshot_sha256"] == bundle["provenance"]["snapshot_source"]["sha256"], "native snapshot binding")
                require(digest(receipt_query(receipt)) == digest(prepared["queries"][lookup[rid]]), "native class mapping")
        require(len(seen) == 50931 and len(lookup) == len(seen), "native denominator")
    return {**result, "affected_ids": len(ids), "affected_classes": len(counts),
            "original_source_reconciliation": bool(verify_sources)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("export").add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify-report")
    verify.add_argument("--bundle", type=Path, required=True, help="bundle JSON or exported directory")
    verify.add_argument("--expected-sha256", help="independently retained bundle digest")
    verify.add_argument("--verify-original-sources", action="store_true", help="optional archive/class ID reconciliation")
    args = parser.parse_args()
    try:
        if args.command == "export":
            result = export(args.output)
        elif args.bundle.is_dir():
            result = verify_directory(args.bundle, args.verify_original_sources, args.expected_sha256)
        else:
            result = verify_bundle(load(args.bundle), expected_sha256=args.expected_sha256)
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, "audit verification failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
