"""Portable retained-evidence reports with independent finite raw verification.

Hashes bind content. They do not authenticate an issuer, prove a source read,
establish live freshness, or establish actual hidden-domain membership.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
from itertools import product
import json
from pathlib import Path

from logistics_validation.catalog_audit import (
    ALPHABET, BASELINE, PROFILES, Rule, catalog_json, reference_time,
    reference_verdict, weak_orders,
)
from logistics_validation.domain_audit import reference_domain_contains
from logistics_validation.focused_diagnostics import Problem, freeze, projection
from logistics_validation.standards_epcis import independent_document_oracle

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "retained-evidence-audit/v1"
SCOPE = (
    "Conditional on truthful retained whole-field observations, a complete visible "
    "base projection, an unchanged source snapshot, and actual membership in the "
    "declared completion domain. A nonempty compatible fiber does not establish "
    "hidden-domain membership. Hashes provide integrity binding, not source "
    "authentication or live freshness. EPCIS reports concern only the authored "
    "finite selected-clause domain, not complete standards conformance."
)
ROBUST_REQUIREMENT = (
    "Every two new-domain completions agreeing on retained observations and all "
    "blocks in a returned set have equal new verdicts; return all inclusion-minimal "
    "such unread-block sets. This is not an adaptive plan or an actual-value minimum."
)
SOURCE_FILES = (
    "src/logistics_validation/audit_report.py",
    "src/logistics_validation/catalog_audit.py",
    "src/logistics_validation/focused_diagnostics.py",
    "src/logistics_validation/standards_epcis.py",
    "src/logistics_validation/domain_audit.py",
    "src/logistics_validation/acquisition.py",
    "src/logistics_validation/model.py",
    "src/logistics_validation/revision_diagnostics.py",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def catalog_from_content(content):
    """Parse the existing four-profile authored catalog fragment, without files."""
    require(isinstance(content, dict) and set(content) == set(PROFILES), "catalog profiles")
    rules = []
    for profile in PROFILES:
        row = content[profile]
        require(isinstance(row, dict) and set(row) == {"required", "forbidden", "edges"}, "catalog fields")
        memberships = []
        for field in ("required", "forbidden"):
            values = row[field]
            require(isinstance(values, list) and all(v in ALPHABET for v in values)
                    and len(values) == len(set(values)), "catalog membership")
            memberships.append(frozenset(ALPHABET.index(v) for v in values))
        edges = row["edges"]
        require(isinstance(edges, list) and all(isinstance(e, list) and len(e) == 2
                and all(v in ALPHABET for v in e) and e[0] != e[1] for e in edges), "catalog edges")
        encoded = [tuple(ALPHABET.index(v) for v in e) for e in edges]
        require(len(encoded) == len(set(encoded)), "duplicate catalog edge")
        rules.append(Rule(*memberships, frozenset(encoded)))
    return tuple(rules)


def receipt_query(receipt):
    """The native receipt v1 binding, preserving repeated base and literal clocks."""
    fields = {"schema_version", "snapshot_sha256", "catalog_sha256", "domain_version",
              "activities", "observed", "verdict", "receipt_id"}
    require(isinstance(receipt, dict) and set(receipt) == fields, "receipt fields")
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1, "receipt version")
    require(type(receipt["verdict"]) is bool, "receipt verdict")
    require(isinstance(receipt["receipt_id"], str) and bool(receipt["receipt_id"]), "receipt ID")
    require(_hash(receipt["snapshot_sha256"]) and _hash(receipt["catalog_sha256"]), "receipt digest")
    activities = receipt["activities"]
    require(isinstance(activities, list) and all(a in ALPHABET for a in activities), "receipt activities")
    base = tuple(dict.fromkeys(ALPHABET.index(a) for a in activities))
    observed = receipt["observed"]
    require(isinstance(observed, dict) and not set(observed) - {"profile", "first_times"}, "receipt observations")
    mask, values = 0, []
    if "profile" in observed:
        require(observed["profile"] in PROFILES, "receipt profile")
        mask |= 1
        values.append(PROFILES.index(observed["profile"]))
    if "first_times" in observed:
        times = observed["first_times"]
        require(isinstance(times, dict) and set(times) == set(activities), "complete timestamp block")
        clocks = [reference_time(times[ALPHABET[a]]) for a in base]
        ranks = {v: i for i, v in enumerate(sorted(set(clocks)))}
        mask |= 2
        values.append(tuple(ranks[v] for v in clocks))
    return dict(base=base, mask=mask, observed=tuple(values), old_verdict=receipt["verdict"])


def domain_content(problem, version):
    if problem.procurement:
        require(version in {"cartesian:v1", "chronological:v1", "consignment_exclusion:v1", "both:v1"}, "unsupported domain")
        guarantees = {"cartesian:v1": [], "chronological:v1": ["chronological"],
                      "consignment_exclusion:v1": ["consignment_exclusion"],
                      "both:v1": ["chronological", "consignment_exclusion"]}[version]
        return {"id": version, "alphabet": list(ALPHABET), "profiles": list(PROFILES),
                "clock_domain": "all canonical weak orders of complete first timestamps",
                "guarantees": guarantees}
    require(version == "selected-clause-cartesian:v1", "unsupported EPCIS domain")
    return {"id": version, "model": problem.name, "blocks": list(problem.blocks),
            "categories": [list(v) for v in problem.spec["domains"]],
            "visible_base": problem.spec["metadata"]["visible_base"], "guarantees": []}


def predicate_content(problem, new):
    """Bind the authored predicate to its actual source and selected clauses."""
    spec = problem.spec
    return {"model": problem.name, "version": "new" if new else "old",
            "contract": spec["metadata"]["new_contract" if new else "old_contract"],
            "clauses": spec["metadata"]["clauses"],
            "authored_source": "src/logistics_validation/standards_epcis.py",
            "authored_source_sha256": file_digest(ROOT / "src/logistics_validation/standards_epcis.py")}


class AdapterContractError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def validate_envelope(envelope, snapshot, fields, required_guarantees=()):
    """Check assertions made by a mock source; this does not authenticate them."""
    def check(condition, code):
        if not condition:
            raise AdapterContractError(code)
    check(_hash(snapshot) and envelope["snapshot_sha256"] == snapshot, "snapshot_mismatch")
    check(isinstance(envelope["epoch"], str) and bool(envelope["epoch"]), "missing_epoch")
    reads = envelope["reads"]
    check(set(reads) == set(fields), "read_set_mismatch")
    for read in reads.values():
        check(read.get("ok") is True, "acquisition_failed")
        check(read.get("snapshot_sha256") == snapshot and read.get("epoch") == envelope["epoch"], "snapshot_mismatch")
        check(read.get("complete") is True, "incomplete_field")
    for name in required_guarantees:
        valid = any(a.get("id") == name and a.get("version") == "v1"
                    and a.get("scope") == "snapshot" and a.get("snapshot_sha256") == snapshot
                    for a in envelope.get("attestations", []))
        check(valid, "missing_snapshot_attestation")
        withdrawn = any(r.get("id") == name and r.get("scope") == "snapshot"
                        and r.get("snapshot_sha256") == snapshot for r in envelope.get("revocations", []))
        check(not withdrawn, "snapshot_attestation_revoked")
    return True


def mock_envelope(snapshot, fields, guarantees=(), epoch="mock-snapshot-1"):
    return {"source_kind": "offline mock assertions; no live-system validation",
            "snapshot_sha256": snapshot, "epoch": epoch,
            "reads": {name: {"ok": True, "complete": True, "snapshot_sha256": snapshot, "epoch": epoch}
                      for name in fields},
            "attestations": [{"id": name, "version": "v1", "scope": "snapshot", "snapshot_sha256": snapshot}
                             for name in guarantees], "revocations": []}


def _raw_label(problem, raw, new):
    if problem.procurement:
        return reference_verdict(raw, problem.catalog if new else BASELINE)
    labels = independent_document_oracle(raw)
    require(labels["supported"], "raw EPCIS witness outside selected scope")
    return labels["compliant_selected" if new else "compatible_selected"]


def _member(problem, raw, version):
    return reference_domain_contains(raw, version.split(":")[0]) if problem.procurement else True


def _raw_rows(problem, query, receipt, old_domain, new_domain):
    """Enumerate only this visible base; never consume compiled truth/fiber tables."""
    base = tuple(query["base"])
    states = (product(range(len(PROFILES)), weak_orders(len(base))) if problem.procurement
              else product(*problem.spec["domains"]))
    for state in states:
        if projection(state, query["mask"]) != freeze(query["observed"]):
            continue
        raw = problem.raw(base, state)
        if problem.procurement:
            raw["activities"] = deepcopy(receipt["activities"])
            raw.update(deepcopy(receipt["observed"]))
        yield state, raw, _member(problem, raw, old_domain), _member(problem, raw, new_domain), \
            _raw_label(problem, raw, False), _raw_label(problem, raw, True)


def raw_summary(problem, query, receipt, old_domain, new_domain):
    rows = list(_raw_rows(problem, query, receipt, old_domain, new_domain))
    old_rows, new_rows = [r for r in rows if r[2]], [r for r in rows if r[3]]
    old_labels, new_labels = sorted({r[4] for r in old_rows}), sorted({r[5] for r in new_rows})
    valid = bool(old_rows) and old_labels == [query["old_verdict"]]
    status = ("invalid_receipt" if not valid else "unsupported" if not new_rows else
              "insufficient" if len(new_labels) == 2 else "safe" if new_labels == [query["old_verdict"]]
              else "stale_verdict")
    succeeds = []
    if valid and new_rows:
        for additional in range(1 << problem.count):
            if additional & query["mask"]:
                continue
            assignments = defaultdict(set)
            for state, _, _, _, _, label in new_rows:
                assignments[projection(state, additional)].add(label)
            if all(len(labels) == 1 for labels in assignments.values()):
                succeeds.append(additional)
    robust = [a for a in succeeds if not any(b != a and b & a == b for b in succeeds)]
    witnesses = []
    for label in new_labels if valid else []:
        row = next(r for r in new_rows if r[5] == label)
        witnesses.append({"old_verdict": row[4], "new_verdict": row[5],
                          "old_domain_member": row[2], "new_domain_member": row[3], "raw": row[1]})
    return {"status": status, "old_valid": valid, "old_verdict_candidates": old_labels,
            "new_verdict_candidates": new_labels,
            "robust_additional_sets": [[name for i, name in enumerate(problem.blocks) if m & (1 << i)] for m in robust],
            "labeled_witnesses": witnesses,
            "old_completion_classes": len(old_rows), "new_completion_classes": len(new_rows)}


def _check_procurement_witness(problem, raw, receipt, new_domain):
    """Check concrete compatibility without fixing unread clocks to one origin.

    The finite abstraction represents every supported weak clock order. Its
    canonical 2020 clock strings are generator choices, not domain constraints.
    Retained literals and the complete repeated activity sequence remain exact.
    """
    require(isinstance(raw, dict) and set(raw) == {"activities", "profile", "first_times"},
            "procurement witness fields")
    complete = {**receipt, "activities": raw["activities"],
                "observed": {"profile": raw["profile"], "first_times": raw["first_times"]}}
    # Reuse only the strict raw schema/parser, not compiled labels or fibers.
    # This checks a supported profile and exactly one supported clock per
    # present activity, including the valid empty-base/empty-clock case.
    receipt_query(complete)
    require(digest(raw["activities"]) == digest(receipt["activities"])
            and all(digest(raw[name]) == digest(value) for name, value in receipt["observed"].items())
            and _member(problem, raw, new_domain), "witness does not preserve observations/domain")


def make_bundle(specs, provenance=None):
    """Export representative requests; optionally cross-check saved engine results."""
    from logistics_validation.revision_diagnostics import validate_query
    artifacts, reports = {}, []

    def artifact(kind, identity, content):
        item = {"kind": kind, "identity": identity, "content": deepcopy(content), "content_sha256": digest(content)}
        key = digest(item)
        artifacts[key] = item
        return key

    for spec in specs:
        problem = spec["problem"]
        query = validate_query(problem, spec["query"])
        receipt = deepcopy(spec.get("receipt"))
        old_domain = spec.get("old_domain", "cartesian:v1" if problem.procurement else "selected-clause-cartesian:v1")
        new_domain = spec.get("new_domain", old_domain)
        if problem.procurement:
            require(freeze(receipt_query(receipt)["observed"]) == freeze(query["observed"])
                    and digest(receipt_query(receipt)) == digest(query), "receipt/query mismatch")
            require(receipt["catalog_sha256"] == digest(catalog_json(BASELINE)), "receipt old catalog mismatch")
            require(receipt["domain_version"] == old_domain, "receipt old domain mismatch")
            snapshot, receipt_id = receipt["snapshot_sha256"], receipt["receipt_id"]
        else:
            snapshot, receipt_id = spec["snapshot_sha256"], spec["receipt_id"]
            require(_hash(snapshot), "synthetic snapshot digest")
            receipt = {"schema_version": 1, "receipt_id": receipt_id, "snapshot_sha256": snapshot,
                       "query": deepcopy(query), "synthetic": True}
        bindings = {}
        for side, new, version in (("old", False, old_domain), ("new", True, new_domain)):
            body = catalog_json(problem.catalog if new else BASELINE) if problem.procurement else predicate_content(problem, new)
            kind = "catalog" if problem.procurement else "authored_predicate"
            identity = spec.get(side + "_identity", problem.name + (":target" if new else ":baseline"))
            bindings[side + "_rule"] = artifact(kind, identity, body)
            bindings[side + "_domain"] = artifact("completion_domain", version, domain_content(problem, version))
        fields = (["activity_projection"] + list(receipt["observed"]) if problem.procurement else
                  ["visible_base"] + [name for i, name in enumerate(problem.blocks) if query["mask"] & (1 << i)])
        guarantees = sorted(set(domain_content(problem, old_domain)["guarantees"] + domain_content(problem, new_domain)["guarantees"]))
        envelope = deepcopy(spec.get("envelope", mock_envelope(snapshot, fields, guarantees)))
        validate_envelope(envelope, snapshot, fields, guarantees)
        summary = raw_summary(problem, query, receipt, old_domain, new_domain)
        if "diagnostic" in spec:
            saved = spec["diagnostic"]
            require(summary["status"] == saved["status"], "saved status disagrees with raw replay")
            names = [[n for i, n in enumerate(problem.blocks) if m & (1 << i)] for m in saved["robust_masks"]]
            require(summary["robust_additional_sets"] == names, "saved robust requirement disagrees with raw replay")
        require(isinstance(spec["request_id"], str) and bool(spec["request_id"]), "request ID")
        report = {"schema_version": SCHEMA, "request_id": spec["request_id"], "receipt_id": receipt_id,
                  "problem": problem.name, "query": query, "receipt": receipt,
                  "receipt_sha256": digest(receipt), "observed_sha256": digest({"query": query, "receipt": receipt}),
                  "snapshot_sha256": snapshot, "bindings": bindings, "adapter_envelope": envelope,
                  "conditional_scope": SCOPE, "robust_requirement": ROBUST_REQUIREMENT, **summary}
        report["report_sha256"] = digest(report)
        reports.append(report)
    require(len({r["request_id"] for r in reports}) == len(reports), "duplicate request ID")
    bundle = {"schema_version": SCHEMA, "artifacts": artifacts, "reports": reports,
              "provenance": deepcopy(provenance or {}),
              "source_hashes": {p: file_digest(ROOT / p) for p in SOURCE_FILES}}
    bundle["bundle_sha256"] = digest(bundle)
    return json.loads(canonical(bundle))


def verify_bundle(bundle, *, expected_sha256=None, source_root=ROOT):
    """No benchmark input, native archive, saved class table, or solver required."""
    from logistics_validation.revision_diagnostics import validate_query
    require(bundle.get("schema_version") == SCHEMA, "bundle schema version")
    checksum = bundle.get("bundle_sha256")
    require(checksum == digest({k: v for k, v in bundle.items() if k != "bundle_sha256"}), "bundle integrity mismatch")
    if expected_sha256 is not None:
        require(checksum == expected_sha256, "external bundle digest mismatch")
    require(set(bundle["source_hashes"]) == set(SOURCE_FILES), "source pin set mismatch")
    for path, expected in bundle["source_hashes"].items():
        require(file_digest(Path(source_root) / path) == expected, "source digest mismatch: " + path)
    for key, item in bundle["artifacts"].items():
        require(key == digest(item) and item["content_sha256"] == digest(item["content"]), "artifact content mismatch")
    request_ids = set()
    for report in bundle["reports"]:
        require(report["schema_version"] == SCHEMA, "report schema version")
        require(isinstance(report["request_id"], str) and bool(report["request_id"]), "request ID")
        require(report["request_id"] not in request_ids, "duplicate request ID")
        request_ids.add(report["request_id"])
        require(report["report_sha256"] == digest({k: v for k, v in report.items() if k != "report_sha256"}), "report integrity mismatch")
        receipt, bindings = report["receipt"], report["bindings"]
        require(isinstance(report["receipt_id"], str) and bool(report["receipt_id"]), "receipt ID")
        require(report["receipt_id"] == receipt["receipt_id"], "receipt ID mix")
        require(report["receipt_sha256"] == digest(receipt), "receipt digest mismatch")
        require(report["snapshot_sha256"] == receipt["snapshot_sha256"], "snapshot mismatch")
        require(report["conditional_scope"] == SCOPE and report["robust_requirement"] == ROBUST_REQUIREMENT, "scope mismatch")
        artifacts = {key: bundle["artifacts"][value] for key, value in bindings.items()}
        require(set(artifacts) == {"old_rule", "new_rule", "old_domain", "new_domain"}, "binding set mismatch")
        procurement = report["problem"].startswith("procurement_")
        require(all(artifacts[side + "_rule"]["kind"] == ("catalog" if procurement else "authored_predicate")
                    and artifacts[side + "_domain"]["kind"] == "completion_domain" for side in ("old", "new")), "artifact kind mismatch")
        problem = Problem(report["problem"], catalog_from_content(artifacts["new_rule"]["content"]) if procurement else None)
        query = validate_query(problem, report["query"])
        require(report["observed_sha256"] == digest({"query": query, "receipt": receipt}), "observed binding mismatch")
        if procurement:
            require(digest(receipt_query(receipt)) == digest(query), "receipt/query mismatch")
            require(artifacts["old_rule"]["content"] == catalog_json(BASELINE), "unsupported old catalog")
            require(receipt["catalog_sha256"] == artifacts["old_rule"]["content_sha256"], "receipt old catalog mismatch")
            require(receipt["domain_version"] == artifacts["old_domain"]["identity"], "receipt old domain mismatch")
        else:
            require(set(receipt) == {"schema_version", "receipt_id", "snapshot_sha256", "query", "synthetic"}
                    and type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
                    and receipt.get("synthetic") is True and digest(receipt["query"]) == digest(query), "synthetic receipt binding")
            for side, new in (("old", False), ("new", True)):
                require(artifacts[side + "_rule"]["content"] == predicate_content(problem, new), "authored predicate mismatch")
        versions = [artifacts[side + "_domain"]["identity"] for side in ("old", "new")]
        for side, version in zip(("old", "new"), versions):
            require(artifacts[side + "_domain"]["content"] == domain_content(problem, version), "domain content mismatch")
        fields = (["activity_projection"] + list(receipt["observed"]) if procurement else
                  ["visible_base"] + [n for i, n in enumerate(problem.blocks) if query["mask"] & (1 << i)])
        guarantees = {g for v in versions for g in domain_content(problem, v)["guarantees"]}
        validate_envelope(report["adapter_envelope"], report["snapshot_sha256"], fields, guarantees)
        expected = raw_summary(problem, query, receipt, *versions)
        require(type(report["old_valid"]) is bool, "old_valid must be Boolean")
        require(all(isinstance(report[f], list) and all(type(label) is bool for label in report[f])
                    for f in ("old_verdict_candidates", "new_verdict_candidates")), "verdict candidates must be Boolean lists")
        require(all(type(report[f]) is int and report[f] >= 0
                    for f in ("old_completion_classes", "new_completion_classes")), "completion counts must be integers")
        for field, value in expected.items():
            if field != "labeled_witnesses":
                require(report[field] == value, "raw verification failed: " + field)
        # Any supported procurement witness may be used. EPCIS still uses the
        # expressly finite authored document representatives of its adapter.
        witnesses = report["labeled_witnesses"]
        require(len(witnesses) == len(expected["labeled_witnesses"]), "witness count")
        require(sorted(w["new_verdict"] for w in witnesses) ==
                sorted(w["new_verdict"] for w in expected["labeled_witnesses"]), "witness label coverage")
        compatible_raw = (None if procurement else
                          {digest(row[1]) for row in _raw_rows(problem, query, receipt, *versions) if row[3]})
        for witness in witnesses:
            raw = witness["raw"]
            if procurement:
                _check_procurement_witness(problem, raw, receipt, versions[1])
            else:
                require(digest(raw) in compatible_raw, "witness does not preserve observations/domain")
            for side, new, version in (("old", False, versions[0]), ("new", True, versions[1])):
                require(type(witness[side + "_verdict"]) is bool and witness[side + "_verdict"] == _raw_label(problem, raw, new), "raw witness label mismatch")
                require(type(witness[side + "_domain_member"]) is bool and witness[side + "_domain_member"] == _member(problem, raw, version), "raw witness domain mismatch")
    return {"status": "passed", "reports": len(bundle["reports"]), "artifacts": len(bundle["artifacts"]),
            "bundle_sha256": checksum, "verification": "raw old sufficiency, new status, all minimal robust sets, literal witnesses and bindings",
            "boundary": "Integrity and conditional finite semantics; no authentication or live freshness"}
