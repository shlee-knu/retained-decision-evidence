"""Check that the benchmark recomputes diagnoses and binds its exact ID work."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("portable_cost", ROOT / "scripts/benchmark_portable_audit_cost.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


@pytest.fixture(scope="module")
def regenerated():
    from logistics_validation.audit_report import make_bundle
    protocol = benchmark.read_json(benchmark.PROTOCOL)
    reference = benchmark.read_json(ROOT / protocol["reference_directory"] / "bundle.json")
    poisoned = deepcopy(reference)
    # Derived outputs must never become generation inputs.
    for report in poisoned["reports"]:
        for field in ("status", "robust_additional_sets", "labeled_witnesses", "new_verdict_candidates"):
            report[field] = "deliberately invalid saved output"
    specs = benchmark.reconstruct_inputs(poisoned)
    assert all("diagnostic" not in entry for entry in specs)
    bundle = make_bundle(specs, reference["provenance"])
    assert bundle == reference
    prepared = benchmark.read_json(ROOT / protocol["mapping_source"])
    ids = benchmark.construct_exact_ids(bundle, prepared)
    payloads = benchmark.serialize_payloads(bundle, ids)
    return protocol, bundle, ids, payloads


def test_generation_ignores_saved_derived_outputs_and_reproduces_bindings(regenerated):
    protocol, bundle, ids, payloads = regenerated
    benchmark.validate_outputs(protocol, bundle, ids, payloads)
    assert json.loads(payloads[0]) == bundle


def test_id_filter_responds_to_fresh_diagnosis(regenerated):
    protocol, bundle, ids, _ = regenerated
    modified = deepcopy(bundle)
    target = next(r for r in modified["reports"]
                  if r["request_id"].startswith("strict:") and r["status"] == "insufficient")
    target["status"] = "safe"
    prepared = benchmark.read_json(ROOT / protocol["mapping_source"])
    altered = benchmark.construct_exact_ids(modified, prepared)
    assert len(altered) < len(ids)
    with pytest.raises(ValueError, match="exact ID denominator/uniqueness"):
        benchmark.validate_outputs(protocol, bundle, altered, benchmark.serialize_payloads(bundle, altered))


def test_trusted_expected_digest_is_enforced(regenerated):
    protocol, bundle, ids, payloads = regenerated
    changed = {**protocol, "expected_bundle_sha256": "0" * 64}
    with pytest.raises(ValueError, match="generated report semantics/bindings differ"):
        benchmark.validate_outputs(changed, bundle, ids, payloads)
