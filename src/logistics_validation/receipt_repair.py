"""Execute a bounded P-first repair against an explicitly authorized snapshot.

The protocol is deliberately sequential, not an optimal acquisition policy.
Content hashes bind a supplied local snapshot; they do not authenticate its
producer or grant permission. Original receipts and scientific engines are not
modified. A replacement is returned only after its new fiber is a singleton.
"""
from __future__ import annotations

from copy import deepcopy
import gzip
import json

from logistics_validation.audit_report import digest, file_digest, raw_summary, receipt_query
from logistics_validation.catalog_audit import BASELINE, catalog_json
from logistics_validation.focused_diagnostics import Problem

BLOCKS = ("profile", "first_times")
DOMAIN = "cartesian:v1"
SCHEMA = "executed-receipt-repair/v1"


class RecoveryError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise RecoveryError(code)


class PublicSnapshot:
    """Immutable public derivative indexed as setup, with counted block calls.

    Opening and parsing the entire file is explicitly outside the logical read
    count; this class makes no claim about physical I/O reduction. Capabilities
    are supplied by the caller for this local public-data experiment.
    """
    def __init__(self, path, expected_sha256, *, capabilities=None):
        require(file_digest(path) == expected_sha256, "snapshot_file_mismatch")
        self.snapshot_sha256 = expected_sha256
        self.rows = {}
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                require(row["case_id"] not in self.rows, "duplicate_source_case")
                self.rows[row["case_id"]] = row
        self.capabilities = dict(capabilities or {})

    def capability(self, receipt, block):
        require(block in BLOCKS, "unsupported_block")
        return self.capabilities.get(block, "access_not_established")

    def read(self, receipt, block):
        require(self.capabilities.get(block) == "authorized", "authorization_not_granted")
        require(receipt["snapshot_sha256"] == self.snapshot_sha256, "snapshot_mismatch")
        row = self.rows.get(receipt["receipt_id"])
        require(row is not None, "source_unavailable")
        require(row["activities"] == receipt["activities"], "base_mismatch")
        require(all(row[name] == value for name, value in receipt["observed"].items()), "retained_value_conflict")
        return {"case_id": row["case_id"], "snapshot_sha256": self.snapshot_sha256,
                "request_receipt_sha256": digest(receipt), "activities": deepcopy(row["activities"]),
                "block": block, "complete": True, "value": deepcopy(row[block])}


class ReceiptRepair:
    """Admit old evidence, acquire P then T as needed, certify a new receipt."""
    def __init__(self, target_name, target_catalog):
        require(target_name.startswith("procurement_"), "target_name")
        self.problem = Problem(target_name, target_catalog)
        self.old_digest = digest(catalog_json(BASELINE))
        self.target_digest = digest(catalog_json(target_catalog))

    def _summary(self, receipt):
        return raw_summary(self.problem, receipt_query(receipt), receipt, DOMAIN, DOMAIN)

    def verify_replacement(self, replacement, original, acquired_blocks):
        """Separately recheck binding, exact retention and new-rule sufficiency.

        The raw-summary new candidates are computed regardless of its BASELINE
        old-valid flag; this verifier checks a target receipt, not a new old
        BASELINE admission. No old Boolean restricts its completion fiber.
        """
        receipt_query(replacement)
        require(replacement["catalog_sha256"] == self.target_digest, "replacement_catalog")
        require(replacement["domain_version"] == DOMAIN, "replacement_domain")
        for key in ("receipt_id", "snapshot_sha256", "activities"):
            require(replacement[key] == original[key], "replacement_" + key)
        expected_keys = set(original["observed"]) | set(acquired_blocks)
        require(set(replacement["observed"]) == expected_keys, "replacement_observed_set")
        require(all(replacement["observed"][key] == value for key, value in original["observed"].items()),
                "replacement_retained_values")
        labels = self._summary(replacement)["new_verdict_candidates"]
        require(labels == [replacement["verdict"]], "replacement_not_certified")
        return True

    def execute(self, receipt, source, *, strategy="adaptive_p_first"):
        """Return a ledger record; never mutate or replace historical evidence.

        An unavailable/denied/failed next P-first acquisition stops this bounded
        policy. It does not prove every other adaptive policy must fail.
        """
        require(isinstance(strategy, str) and strategy in {"adaptive_p_first", "robust_all_first"}, "unsupported_strategy")
        result = {"schema_version": SCHEMA, "source_case_id": None,
                  "strategy": strategy,
                  "target": self.problem.name, "target_catalog_sha256": self.target_digest,
                  "original_receipt_sha256": None, "initial_status": None,
                  "action": "unresolved", "reason": None, "capability_checks": [],
                  "attempted_reads": [], "successful_reads": [], "acquisition_completed": False,
                  "accepted_responses": [],
                  "replacement_receipt": None, "replacement_verified": False}
        try:
            require(isinstance(receipt, dict), "receipt_schema")
            original = deepcopy(receipt)
            receipt_query(original)
            require(original["catalog_sha256"] == self.old_digest, "old_catalog_mismatch")
            require(original["domain_version"] == DOMAIN, "unsupported_domain")
            result["original_receipt_sha256"] = digest(original)
            result["source_case_id"] = original["receipt_id"]
            summary = self._summary(original)
        except (ValueError, TypeError, KeyError, IndexError, OverflowError) as error:
            result.update(action="invalid_receipt", reason=getattr(error, "code", "receipt_schema"))
            return result
        result["initial_status"] = summary["status"]
        result["initial_robust_additional_sets"] = summary["robust_additional_sets"]
        if summary["status"] in {"invalid_receipt", "unsupported"}:
            result.update(action=summary["status"], reason="old_admission_or_domain")
            return result
        current = deepcopy(original)
        fixed_blocks = []
        if strategy == "robust_all_first" and summary["status"] == "insufficient":
            fixed_blocks = min(summary["robust_additional_sets"], key=lambda values: (len(values), values))[:]
            for block in fixed_blocks:
                try:
                    capability = source.capability(deepcopy(current), block)
                except Exception as error:
                    result.update(reason=getattr(error, "code", "capability_failed"))
                    return result
                if not isinstance(capability, str):
                    result["capability_checks"].append({"block": block, "state": "invalid_capability",
                                                        "received_type": type(capability).__name__})
                    result.update(reason="invalid_capability", blocked_block=block)
                    return result
                result["capability_checks"].append({"block": block, "state": capability})
                if capability != "authorized":
                    result.update(reason=capability if capability in {
                        "source_unavailable", "authorization_not_granted", "access_not_established"
                    } else "invalid_capability", blocked_block=block)
                    return result
        while summary["status"] == "insufficient" or fixed_blocks:
            block = fixed_blocks.pop(0) if fixed_blocks else next((name for name in BLOCKS if name not in current["observed"]), None)
            require(block is not None, "complete_fiber_ambiguous")
            if strategy == "adaptive_p_first":
                try:
                    capability = source.capability(deepcopy(current), block)
                except Exception as error:
                    result.update(reason=getattr(error, "code", "capability_failed"))
                    return result
                if not isinstance(capability, str):
                    result["capability_checks"].append({"block": block, "state": "invalid_capability",
                                                        "received_type": type(capability).__name__})
                    result.update(reason="invalid_capability", blocked_block=block)
                    return result
                result["capability_checks"].append({"block": block, "state": capability})
                if capability != "authorized":
                    result.update(reason=capability if capability in {
                        "source_unavailable", "authorization_not_granted", "access_not_established"
                    } else "invalid_capability", blocked_block=block)
                    return result
            result["attempted_reads"].append(block)
            try:
                try:
                    response = source.read(deepcopy(current), block)
                except RecoveryError:
                    raise
                except Exception:
                    raise RecoveryError("read_failed") from None
                require(isinstance(response, dict) and set(response) == {
                    "case_id", "snapshot_sha256", "request_receipt_sha256", "activities", "block", "complete", "value"
                }, "read_envelope_schema")
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
                summary = self._summary(expanded)
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
        self.verify_replacement(replacement, original, result["successful_reads"])
        require(all(replacement["observed"][response["block"]] == response["value"]
                    for response in result["accepted_responses"]), "replacement_acquired_values")
        result.update(action="replaced", reason="acquired_sufficient_evidence" if result["successful_reads"]
                      else "retained_sufficient_evidence", replacement_receipt=replacement,
                      replacement_verified=True, acquisition_completed=bool(result["successful_reads"]))
        return result
