"""Download a byte-hashed public raw-XES mirror if 4TU is under maintenance."""
import json
from pathlib import Path
import requests
from download_sources import ROOT, download

ORIGINAL = "https://data.4tu.nl/file/35ed7122-966a-484e-a0e1-749b64e3366d/864493d1-3a58-47f6-ad6f-27f95f995828"
COMMIT = "f9053eec5c91bd5432bc7d97a0d0e77021a10209"
MIRROR = f"https://media.githubusercontent.com/media/arafatro/CaRuD/{COMMIT}/data/BPI_Challenge_2019.xes"
HASH = "af63bc687fc4152f2123b05c3af7772b37ef3fce2d3f67f812666c9e356baae7"

if __name__ == "__main__":
    provenance = ROOT / "data/provenance"
    provenance.mkdir(parents=True, exist_ok=True)
    source_status = dict(original_url=ORIGINAL, original_doi="10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1")
    # Read-only availability check. Do not attempt to bypass repository maintenance.
    with requests.get(ORIGINAL, stream=True, timeout=30) as r:
        source_status.update(http_status=r.status_code, content_type=r.headers.get("Content-Type"))
        if "text/html" in r.headers.get("Content-Type", ""):
            s = r.text
            source_status["maintenance"] = "offline for maintenance" in s
            (provenance / "4TU_availability.html").write_text(s, encoding="utf-8")
    record = download(MIRROR, "data/raw/bpi/BPI_Challenge_2019.xes",
                      expected_size=728558522, expected_hash=HASH, license_name="CC-BY-4.0 (original DataCite record)")
    record.update(original_doi=source_status["original_doi"], mirror_commit=COMMIT,
                  fidelity="Pinned mirror hash checked; original repository byte identity not independently verified during maintenance")
    (provenance / "bpi_mirror_manifest.json").write_text(json.dumps(dict(availability=source_status, source=record), indent=2), encoding="utf-8")
