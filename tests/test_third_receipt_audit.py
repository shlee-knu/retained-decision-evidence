from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import audit_receipt_tool as audit


def test_independent_universe_and_old_class_census():
    oracle = audit.IndependentOracle()
    assert len(oracle.raws) == 8612
    assert {d: len(list(oracle.valid_classes(d))) for d in audit.DOMAINS} == {
        "cartesian:v1": 10436, "chronological:v1": 1764,
        "consignment_exclusion:v1": 8793, "both:v1": 1505}
    assert oracle.labels["identity"] == oracle.labels["equivalent"]
    assert oracle.labels["identity"] != oracle.labels["label_flip"]


def test_status_oracle_nonvacuity_and_stale_sufficiency():
    assert audit.expected_status(0, 0, False, 1, 1) == "invalid_receipt"
    assert audit.expected_status(2, 3, False, 1, 1) == "invalid_receipt"
    assert audit.expected_status(1, 1, False, 0, 0) == "unsupported"
    assert audit.expected_status(1, 1, False, 2, 3) == "insufficient"
    assert audit.expected_status(1, 1, False, 1, 2) == "stale_verdict"
    assert audit.expected_status(1, 1, False, 1, 1) == "safe"


def test_negative_controls_and_digest_binding():
    oracle = audit.IndependentOracle()
    controls = audit.negative_controls(oracle)
    assert len(controls) == 6
    assert sum(c["status"] == "invalid_receipt" for c in controls) == 3
    first = next(oracle.valid_classes("cartesian:v1"))
    receipt = oracle.receipt("cartesian:v1", first[0], first[1], first[2])
    engine = audit.make_engine("identity", "cartesian:v1", "cartesian:v1")
    assert receipt["catalog_sha256"] == engine.old_digest
    assert engine.revalidate(receipt)["status"] == "safe"


def test_fresh_output_and_no_overwrite(tmp_path):
    output = audit.prepare_output(tmp_path / "fresh")
    (output / "pytest.xml").write_text("fixture")
    (output / "run.log").write_text("fixture")
    assert audit.prepare_output(output) == output
    audit.dump(output / "summary.json", {"original": True})
    with pytest.raises(ValueError, match="populated"):
        audit.prepare_output(output)
    with pytest.raises(FileExistsError):
        audit.dump(output / "summary.json", {"overwritten": True})
    assert (output / "summary.json").read_text().find("original") >= 0
    assert audit.manifest_path(output).startswith("/")
