"""Acquire only public sources; pin versions and retain provenance. No uploads."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[1]
REV = "be2cec02775cafc8d52230303f32134382bcc50b"
FILES = {
    "cq": (145068417, "114a35e9a31f817a3c9efb8513924688706bcedfa85ccd69df696eb5e8eddea2"),
    "hz": (286893611, "9969df2a5c79dadc6149c384e3632eccc0417d01a2575a74db2310e786541c22"),
    "jl": (4736342, None),
    "sh": (228069571, "da875abddbb01ac324106b9b9ce33181e5e8530e77359a12ee68567fd1cc3bbf"),
    "yt": (31532960, "aa5bca7fdaa8c89d4ab50a2ed2b94fb09f608acc49fc1108a1a612e9c0f5a7ad"),
}

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()

def download(url, relpath, *, expected_size=None, expected_hash=None, license_name="see upstream"):
    dst = ROOT / relpath
    dst.parent.mkdir(parents=True, exist_ok=True)
    if not dst.exists():
        with requests.get(url, stream=True, timeout=(20, 120)) as r:
            r.raise_for_status()
            if "text/html" in r.headers.get("Content-Type", ""):
                raise RuntimeError(f"HTML returned instead of data: {url}")
            tmp = dst.with_suffix(dst.suffix + ".part")
            with tmp.open("wb") as f:
                for chunk in r.iter_content(1024 * 1024):
                    if chunk:
                        f.write(chunk)
            tmp.replace(dst)
    digest = sha256(dst)
    if expected_size is not None and dst.stat().st_size != expected_size:
        raise RuntimeError(f"Size mismatch {dst}")
    if expected_hash and digest != expected_hash:
        raise RuntimeError(f"SHA-256 mismatch {dst}")
    record = dict(path=relpath, url=url, size=dst.stat().st_size, sha256=digest,
                  upstream_sha256=expected_hash, license=license_name,
                  acquired_utc=datetime.now(timezone.utc).isoformat())
    print(f"Acquired {relpath}: {record['size']:,} bytes {digest[:12]}", flush=True)
    return record

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cities", nargs="+", default=list(FILES), choices=list(FILES))
    args = p.parse_args()
    metadata = ROOT / "data/provenance"
    metadata.mkdir(parents=True, exist_ok=True)
    records = []
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for city in args.cities:
            size, digest = FILES[city]
            url = f"https://huggingface.co/datasets/Cainiao-AI/LaDe/resolve/{REV}/delivery/delivery_{city}.csv"
            futures.append(pool.submit(download, url, f"data/raw/lade/delivery_{city}.csv",
                                       expected_size=size, expected_hash=digest, license_name="Apache-2.0 (dataset card)"))
        for f in concurrent.futures.as_completed(futures):
            records.append(f.result())
    records.append(download(f"https://huggingface.co/datasets/Cainiao-AI/LaDe/raw/{REV}/README.md",
                            "data/provenance/LaDe_README.md", license_name="Apache-2.0 (dataset card)"))
    records.append(download("https://ref.gs1.org/standards/epcis/2.0.0/epcis-json-schema.json",
                            "data/standards/epcis-json-schema.json", license_name="GS1 terms; retain source, not relicensed"))
    records.append(download("https://ref.gs1.org/standards/epcis/2.0.0/epcis-shacl.ttl",
                            "data/standards/epcis-shacl.ttl", license_name="GS1 terms; retain source, not relicensed"))
    for name, url in [
        ("LaDe_metadata.json", "https://huggingface.co/api/datasets/Cainiao-AI/LaDe"),
        ("BPI2019_datacite.json", "https://api.datacite.org/dois/10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1"),
    ]:
        j = requests.get(url, timeout=30)
        j.raise_for_status()
        (metadata / name).write_text(json.dumps(j.json(), ensure_ascii=False, indent=2), encoding="utf-8")
    (metadata / "sources_manifest.json").write_text(json.dumps(sorted(records, key=lambda x:x["path"]), indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
