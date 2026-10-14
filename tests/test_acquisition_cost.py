"""Transport fairness and semantic edge cases for the new local-cost audit."""
import importlib.util
from pathlib import Path
import sys

import pytest

PATH = Path(__file__).resolve().parents[1] / "scripts/benchmark_acquisition_cost.py"
SPEC = importlib.util.spec_from_file_location("procurement_cost_benchmark", PATH)
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def case(sequence, profile="3-way match, invoice before GR", times=None):
    first = list(dict.fromkeys(sequence))
    return dict(activities=sequence, profile=profile,
                first_times=times or {a: f"2020-01-01T00:00:0{i}.000Z" for i, a in enumerate(first)})


CASES = [
    case([]),
    case(["create"]),
    case(["create", "receive"], "Consignment"),
    case(["create", "receive", "invoice", "clear"], "Consignment"),
    case(["create", "invoice", "receive", "clear"], "3-way match, invoice after GR"),
    case(["create", "invoice", "receive", "clear"]),
    case(["create", "receive", "receive", "invoice", "clear", "invoice"]),
    case(["create", "receive"], "Consignment",
         {"create": "2020-01-01T00:00:00.0000000002Z", "receive": "2020-01-01T00:00:00.0000000001Z"}),
    case(["create", "receive"], "Consignment",
         {"create": "2020-01-01T01:00:00.1+01:00", "receive": "2020-01-01t00:00:00.100z"}),
]


@pytest.mark.parametrize("features", CASES)
def test_direct_and_hand_policies_match_independent_oracle_and_read_masks(features):
    for strict in (False, True):
        expected = not benchmark.expected_violation(features, strict)
        encoded = benchmark.encode_case(features)
        masks = {}
        for method in benchmark.METHODS:
            access = benchmark.SerializedAccessor(encoded)
            assert benchmark.decide(access, strict, method) == expected
            assert access.decodes == bool(access.mask & 1) + bool(access.mask & 2)
            masks[method] = access.mask
        for suffix in ("profile_first", "time_first", "structural"):
            assert masks["hand_" + suffix] == masks["certificate_" + suffix]


def test_direct_baseline_deserializes_both_even_on_early_structural_rejection():
    encoded = benchmark.encode_case(case(["create"]))
    access = benchmark.SerializedAccessor(encoded)
    assert benchmark.direct_full_once(access, strict=False) is False
    assert access.trace == ["profile", "first_times"]
    assert access.bytes_read == len(encoded.profile_bytes) + len(encoded.time_bytes)
    assert access.decodes == 2


def test_all_selective_baselines_skip_both_blocks_when_base_is_decisive():
    encoded = benchmark.EncodedCase((), b"not accessed", b"not accessed")
    # Poison bytes establish lack of reads, not correctness on unsupported hidden
    # metadata. The claimed decision guarantee remains domain-conditional.
    for method in benchmark.METHODS:
        if method.endswith("full_once") or method.endswith("always_both"):
            continue
        access = benchmark.SerializedAccessor(encoded)
        assert benchmark.decide(access, False, method) is False
        assert access.mask == access.bytes_read == access.decodes == 0
