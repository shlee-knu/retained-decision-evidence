from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from urllib.parse import quote
import hashlib
import json
import uuid
import re

BASE = "https://example.org/logistics-research/"
CTX = ["https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld", {
    "research": BASE,
    # Preserve the reference as an RDF edge when JSON-LD is expanded. Without
    # @id coercion its URI-looking value becomes a literal rather than a link.
    "research:predecessor": {"@id": BASE + "predecessor", "@type": "@id"},
}]

def uri(kind: str, value: str) -> str:
    """Explicit dataset namespace, never claim a formally assigned GS1 identifier."""
    if kind == "event":
        # EPCIS event identifiers use UUID URNs; source logs do not assign these.
        return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, BASE + str(value)))
    return BASE + kind + "/" + quote(str(value), safe="")

@dataclass
class Event:
    event_id: str
    object_id: str
    activity: str
    time: str | None
    # Experiment-level reference. Not a normative EPCIS event field.
    ref: str | None = None
    readpoint: str | None = None
    vendor_step: bool = False

    def epcis(self) -> dict:
        obj = {
            "@context": CTX, "type": "ObjectEvent", "action": "OBSERVE",
            "eventID": self.event_id, "epcList": [self.object_id],
            "eventTimeZoneOffset": "+00:00", "bizStep": uri("activity", self.activity),
        }
        if self.vendor_step:
            obj["bizStep"] = "https://example.org/vendor/workflow/" + quote(self.activity, safe="")
        if self.time is not None:
            obj["eventTime"] = self.time
        if self.readpoint:
            obj["readPoint"] = {"id": self.readpoint}
        if self.ref:
            obj["research:predecessor"] = self.ref
        return obj

@dataclass
class Case:
    case_id: str
    dataset: str
    group: str
    profile: str
    source_locator: str
    events: list[Event]
    # Required precedence edges. A==B is allowed in timestamps; positional order matters.
    edges: list[tuple[str, str]]
    required: list[str]
    attributes: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Case":
        z = dict(d)
        z["events"] = [Event(**e) for e in d["events"]]
        z["edges"] = [tuple(x) for x in d["edges"]]
        return cls(**z)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()

def seconds(value: str | None) -> float | None:
    """Approximate compatibility helper; never used for semantic ordering."""
    if not isinstance(value, str):
        return None
    try:
        # RFC 3339 permits lower-case t/z. The common JSON Schema format
        # checker accepts them, so the semantic layer must not silently skip
        # a valid lower-case UTC timestamp. Replace only the terminal zone.
        normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return None
        return dt.timestamp()
    except (TypeError, ValueError):
        return None

_RFC3339 = re.compile(r"(\d{4}-\d{2}-\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})\Z")

def timestamp_key(value: str | None) -> str | None:
    """Exact sortable UTC key, retaining every fractional digit.

    Fixed-width shifted whole seconds followed by a canonical fractional
    string preserve numeric order with ordinary Python/SQLite binary text
    comparison. No float epoch, rounding, or microsecond truncation is used.
    Scope follows the enabled format checker: no leap-second normalization.
    """
    if not isinstance(value, str):
        return None
    match = _RFC3339.fullmatch(value)
    if match is None:
        return None
    day, hh, mm, ss, fraction, zone = match.groups()
    try:
        whole = datetime.fromisoformat(f"{day}T{hh}:{mm}:{ss}")
        delta = whole - datetime(1970, 1, 1)
        integer = delta.days * 86400 + delta.seconds
        if zone.upper() != "Z":
            oh, om = int(zone[1:3]), int(zone[4:6])
            if oh > 23 or om > 59:
                return None
            integer -= (oh * 3600 + om * 60) * (1 if zone[0] == "+" else -1)
        return f"{integer + 10**12:013d}." + (fraction or "").rstrip("0")
    except (TypeError, ValueError):
        return None
