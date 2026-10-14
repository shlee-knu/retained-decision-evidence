"""Conventional enumeration/worklist implementation of the workflow contract.

This comparison implementation reads declarative JSON rules directly. It uses
neither ReceiptRepair nor diagnostic engine/raw_summary/make_bundle calls.
No semantic-result cache is used. The common receipt parser, immutable source
adapter, content digest, report schema, persistence and external verifier are
shared interfaces. This is a bounded reference implementation, not a product.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from itertools import product

from logistics_validation.audit_report import (
    ROBUST_REQUIREMENT, SCHEMA, SCOPE, SOURCE_FILES, ROOT, canonical, digest,
    file_digest, mock_envelope, receipt_query,
)
from logistics_validation.receipt_repair import BLOCKS, DOMAIN, RecoveryError, require

ACTIVITIES = ("create", "receive", "invoice", "clear")
PROFILES = ("3-way match, invoice after GR", "3-way match, invoice before GR", "2-way match", "Consignment")


class OrdinaryWorkflow:
    def __init__(self, old_catalog, target_catalog, target_name="procurement_workflow_strict"):
        self.old_catalog = deepcopy(old_catalog)
        self.target_catalog = deepcopy(target_catalog)
        self.old_digest = digest(old_catalog)
        self.target_digest = digest(target_catalog)
        self.target_name = target_name

    @staticmethod
    def decision(base, profile, ranks, catalog):
        names = tuple(ACTIVITIES[i] for i in base)
        rule = catalog[PROFILES[profile]]
        if any(a not in names for a in rule["required"]) or any(a in names for a in rule["forbidden"]):
            return False
        for a, b in rule["edges"]:
            if b not in names:
                continue
            if a not in names or names.index(a) >= names.index(b):
                return False
            if ranks[names.index(a)] > ranks[names.index(b)]:
                return False
        return True

    def summary(self, receipt, *, witnesses=False):
        query = receipt_query(receipt)
        base, mask, observed = tuple(query["base"]), query["mask"], query["observed"]
        profiles = (observed[0],) if mask & 1 else range(len(PROFILES))
        if mask & 2:
            orders = (observed[-1],)
        else:
            orders = tuple(r for r in product(range(len(base)), repeat=len(base))
                           if not r or set(r) == set(range(max(r) + 1)))
        rows = []
        for p in profiles:
            for ranks in orders:
                rows.append((p, ranks, self.decision(base, p, ranks, self.old_catalog),
                             self.decision(base, p, ranks, self.target_catalog)))
        old_labels, new_labels = sorted({r[2] for r in rows}), sorted({r[3] for r in rows})
        valid = bool(rows) and old_labels == [receipt["verdict"]]
        status = ("invalid_receipt" if not valid else "unsupported" if not rows else
                  "insufficient" if len(new_labels) > 1 else
                  "safe" if new_labels == old_labels else "stale_verdict")
        robust = []
        if valid:
            for add in range(4):
                if add & mask or any(prior & add == prior for prior in robust):
                    continue
                groups = defaultdict(set)
                for p, ranks, _, label in rows:
                    groups[(p if add & 1 else None, ranks if add & 2 else None)].add(label)
                if groups and all(len(labels) == 1 for labels in groups.values()):
                    robust.append(add)
        report = {"status": status, "old_valid": valid,
                  "old_verdict_candidates": old_labels, "new_verdict_candidates": new_labels,
                  "robust_additional_sets": [[block for i, block in enumerate(BLOCKS) if add & (1 << i)] for add in robust],
                  "old_completion_classes": len(rows), "new_completion_classes": len(rows), "labeled_witnesses": []}
        if witnesses and valid:
            for label in new_labels:
                p, ranks, old, new = next(row for row in rows if row[3] == label)
                raw = {"activities": deepcopy(receipt["activities"]), "profile": PROFILES[p],
                       "first_times": {ACTIVITIES[a]: f"2020-01-01T00:00:0{rank}Z" for a, rank in zip(base, ranks)}}
                raw.update(deepcopy(receipt["observed"]))
                report["labeled_witnesses"].append({"old_verdict": old, "new_verdict": new,
                                                   "old_domain_member": True, "new_domain_member": True, "raw": raw})
        return report

    def construct_reports(self, prepared, protocol):
        artifacts, reports = {}, []
        def artifact(kind, identity, body):
            item = {"kind": kind, "identity": identity, "content": deepcopy(body), "content_sha256": digest(body)}
            key = digest(item)
            artifacts[key] = item
            return key
        domain = {"id": DOMAIN, "alphabet": list(ACTIVITIES), "profiles": list(PROFILES),
                  "clock_domain": "all canonical weak orders of complete first timestamps", "guarantees": []}
        bindings = {"old_rule": artifact("catalog", protocol["old_catalog"], self.old_catalog),
                    "new_rule": artifact("catalog", protocol["target_catalog"], self.target_catalog),
                    "old_domain": artifact("completion_domain", DOMAIN, domain),
                    "new_domain": artifact("completion_domain", DOMAIN, domain)}
        for row in prepared["classes"]:
            receipt = deepcopy(row["receipt"])
            query = receipt_query(receipt)
            require(digest(query) == digest(row["query"]), "receipt/query mismatch")
            require(receipt["catalog_sha256"] == self.old_digest and receipt["domain_version"] == DOMAIN, "old binding")
            report = {"schema_version": SCHEMA, "request_id": "class:" + str(row["class_index"]),
                      "receipt_id": receipt["receipt_id"], "problem": self.target_name,
                      "query": query, "receipt": receipt, "receipt_sha256": digest(receipt),
                      "observed_sha256": digest({"query": query, "receipt": receipt}),
                      "snapshot_sha256": receipt["snapshot_sha256"], "bindings": deepcopy(bindings),
                      "adapter_envelope": mock_envelope(receipt["snapshot_sha256"], ["activity_projection"] + list(receipt["observed"])),
                      "conditional_scope": SCOPE, "robust_requirement": ROBUST_REQUIREMENT,
                      **self.summary(receipt, witnesses=True)}
            report["report_sha256"] = digest(report)
            reports.append(report)
        bundle = {"schema_version": SCHEMA, "artifacts": artifacts, "reports": reports,
                  "provenance": {"kind": "integrated local workflow", "class_definition": "normalized retained observation plus old verdict",
                                 "native_receipts": len(prepared["receipts"]),
                                 "receipt_store_sha256": protocol["pinned_files"][protocol["receipt_source"]]},
                  "source_hashes": {name: file_digest(ROOT / name) for name in SOURCE_FILES}}
        bundle["bundle_sha256"] = digest(bundle)
        import json
        bundle = json.loads(canonical(bundle))
        class_reports = {int(r["request_id"].split(":")[1]): r for r in bundle["reports"]}
        ids = [{"receipt_id": rid, "class_index": index, "obligation": "acquire profile"}
               for rid, index in prepared["mapping"] if class_reports[index]["status"] == "insufficient"]
        require(all(class_reports[r["class_index"]]["robust_additional_sets"] == [["profile"]] for r in ids), "strict-only obligation")
        return {"bundle": bundle, "class_reports": class_reports, "ids": ids,
                "status_counts": dict(Counter(class_reports[index]["status"] for _, index in prepared["mapping"]))}

    def execute(self, receipt, source):
        result = {"schema_version": "executed-receipt-repair/v1", "source_case_id": None,
                  "strategy": "adaptive_p_first", "target": self.target_name,
                  "target_catalog_sha256": self.target_digest, "original_receipt_sha256": None,
                  "initial_status": None, "action": "unresolved", "reason": None,
                  "capability_checks": [], "attempted_reads": [], "successful_reads": [],
                  "acquisition_completed": False, "accepted_responses": [],
                  "replacement_receipt": None, "replacement_verified": False}
        try:
            original = deepcopy(receipt)
            receipt_query(original)
            require(original["catalog_sha256"] == self.old_digest, "old_catalog_mismatch")
            require(original["domain_version"] == DOMAIN, "unsupported_domain")
            result["source_case_id"] = original["receipt_id"]
            result["original_receipt_sha256"] = digest(original)
            current = deepcopy(original)
            summary = self.summary(current)
        except (ValueError, TypeError, KeyError, IndexError, OverflowError) as error:
            result.update(action="invalid_receipt", reason=getattr(error, "code", "receipt_schema"))
            return result
        result["initial_status"] = summary["status"]
        result["initial_robust_additional_sets"] = summary["robust_additional_sets"]
        if summary["status"] in {"invalid_receipt", "unsupported"}:
            result.update(action=summary["status"], reason="old_admission_or_domain")
            return result
        while len(summary["new_verdict_candidates"]) == 2:
            block = next((b for b in BLOCKS if b not in current["observed"]), None)
            require(block is not None, "complete_fiber_ambiguous")
            try:
                capability = source.capability(deepcopy(current), block)
            except Exception as error:
                result.update(reason=getattr(error, "code", "capability_failed"))
                return result
            if not isinstance(capability, str):
                result["capability_checks"].append({"block": block, "state": "invalid_capability", "received_type": type(capability).__name__})
                result.update(reason="invalid_capability", blocked_block=block)
                return result
            result["capability_checks"].append({"block": block, "state": capability})
            if capability != "authorized":
                reason = capability if capability in {"source_unavailable", "authorization_not_granted", "access_not_established"} else "invalid_capability"
                result.update(reason=reason, blocked_block=block)
                return result
            result["attempted_reads"].append(block)
            try:
                try:
                    response = source.read(deepcopy(current), block)
                except RecoveryError:
                    raise
                except Exception:
                    raise RecoveryError("read_failed") from None
                require(isinstance(response, dict) and set(response) == {"case_id", "snapshot_sha256", "request_receipt_sha256", "activities", "block", "complete", "value"}, "read_envelope_schema")
                require(response["case_id"] == current["receipt_id"], "source_case_mismatch")
                require(response["snapshot_sha256"] == current["snapshot_sha256"], "snapshot_mismatch")
                require(response["request_receipt_sha256"] == digest(current), "read_request_mismatch")
                require(response["activities"] == current["activities"], "base_mismatch")
                require(response["block"] == block, "read_block_mismatch")
                require(response["complete"] is True, "incomplete_block")
                expanded = deepcopy(current)
                expanded["observed"][block] = deepcopy(response["value"])
                try:
                    receipt_query(expanded)
                except (ValueError, TypeError, KeyError, IndexError):
                    raise RecoveryError("unsupported_acquired_value") from None
                summary = self.summary(expanded)
                require(summary["status"] not in {"invalid_receipt", "unsupported"}, "acquired_value_conflicts_with_old_receipt")
            except (RecoveryError, OSError) as error:
                result.update(reason=getattr(error, "code", "read_failed"), blocked_block=block)
                return result
            current = expanded
            result["successful_reads"].append(block)
            result["accepted_responses"].append(deepcopy(response))
        replacement = deepcopy(current)
        replacement["catalog_sha256"] = self.target_digest
        replacement["verdict"] = summary["new_verdict_candidates"][0]
        receipt_query(replacement)
        require(replacement["catalog_sha256"] == self.target_digest, "replacement_catalog")
        require(replacement["domain_version"] == DOMAIN, "replacement_domain")
        require(all(replacement[k] == original[k] for k in ("receipt_id", "snapshot_sha256", "activities")), "replacement_binding")
        require(set(replacement["observed"]) == set(original["observed"]) | set(result["successful_reads"]), "replacement_observed_set")
        require(all(replacement["observed"][k] == v for k, v in original["observed"].items()), "replacement_retained_values")
        require(self.summary(replacement)["new_verdict_candidates"] == [replacement["verdict"]], "replacement_not_certified")
        require(all(replacement["observed"][r["block"]] == r["value"] for r in result["accepted_responses"]), "replacement_acquired_values")
        result.update(action="replaced", reason="acquired_sufficient_evidence" if result["successful_reads"] else "retained_sufficient_evidence",
                      replacement_receipt=replacement, replacement_verified=True,
                      acquisition_completed=bool(result["successful_reads"]))
        return result
