"""Compare the acquired BPI 2019 mirror with the original deposit's checksum.

The original archive is not redownloaded. The repository advertises an MD5;
its size and MD5 are compared to the complete local bytes. A local SHA-256 is
also recorded. This is deposit-checksum verification, not a second download.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.figshare.com/v2/articles/12715853"
DOI = "10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-metadata", action="store_true")
    args = parser.parse_args()
    metadata_path = ROOT / "data/provenance/bpi2019_original_figshare_metadata.json"
    if args.refresh_metadata or not metadata_path.exists():
        with urllib.request.urlopen(API, timeout=30) as response:
            metadata = json.load(response)
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
    metadata = json.loads(metadata_path.read_text())
    if metadata["doi"] != DOI:
        raise ValueError("Original deposit DOI differs")
    original = next(f for f in metadata["files"] if f["name"] == "BPI_Challenge_2019.xes")
    raw = ROOT / "data/raw/bpi/BPI_Challenge_2019.xes"
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with raw.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            md5.update(block)
            sha256.update(block)
    report = {
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "doi": DOI, "metadata_url": API,
        "metadata_path": str(metadata_path.relative_to(ROOT)),
        "metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
        "raw_path": str(raw.relative_to(ROOT)),
        "raw_size": raw.stat().st_size,
        "raw_md5": md5.hexdigest(), "raw_sha256": sha256.hexdigest(),
        "deposit_file": original,
        "size_matches": raw.stat().st_size == original["size"],
        "md5_matches": md5.hexdigest() == original["computed_md5"],
        "original_archive_redownloaded": False,
        "verification_scope": "Complete local bytes match the size and MD5 advertised by the original repository; no second archive download.",
    }
    if not report["size_matches"] or not report["md5_matches"]:
        raise ValueError("The acquired archive differs from the original deposit's checksum")
    output = ROOT / "results/expanded/provenance/bpi2019_deposit_verification.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
