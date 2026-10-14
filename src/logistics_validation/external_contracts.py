"""Authored cross-domain observation contracts and explicit block-read policies.

Certificates are conditional on a complete, correct activity projection and
well-formed relevant numeric/time values. They are ordinary short-circuit
certificates, not a novel optimal-acquisition algorithm or business truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from fractions import Fraction
import json
import re
from typing import Callable

APPROVALS = frozenset(("Permit FINAL_APPROVED by SUPERVISOR", "Permit FINAL_APPROVED by DIRECTOR"))
TRAFFIC_CONTRACTS = ("traffic_cumulative", "traffic_final", "traffic_timestamp_groups", "traffic_recorded_recurrence")
CONTRACTS = TRAFFIC_CONTRACTS + ("travel_first_approval",)
POLICIES = ("full_once", "hand_guard", "generic_certificate")
NUMBER = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")
CLOCK = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})\Z")


class Unsupported(ValueError):
    pass


def number(value: str | None) -> Fraction:
    if not isinstance(value, str) or not NUMBER.fullmatch(value):
        raise Unsupported("Expected a finite ASCII decimal numeric lexeme")
    return Fraction(Decimal(value))


def clock(value: str | None) -> tuple[int, str]:
    """Exact UTC whole-second key and canonical arbitrary-precision fraction."""
    if not isinstance(value, str) or not (match := CLOCK.fullmatch(value)):
        raise Unsupported("Expected an RFC3339 timestamp with an explicit known offset")
    y, mo, d, h, mi, s, fraction, zone = match.groups()
    if zone == "-00:00":
        raise Unsupported("Unknown local offset is outside the completion domain")
    try:
        whole = (date(int(y), int(mo), int(d)).toordinal() - date(1970, 1, 1).toordinal()) * 86400
        hh, mm, ss = int(h), int(mi), int(s)
        if hh > 23 or mm > 59 or ss > 59:
            raise ValueError("Clock component out of range; leap seconds unsupported")
        whole += hh * 3600 + mm * 60 + ss
        if zone.upper() != "Z":
            zh, zm = int(zone[1:3]), int(zone[4:6])
            if zh > 23 or zm > 59:
                raise ValueError("Offset out of range")
            whole -= (zh * 3600 + zm * 60) * (1 if zone[0] == "+" else -1)
        return whole, (fraction or "").rstrip("0")
    except ValueError as exc:
        raise Unsupported(str(exc)) from exc


@dataclass(frozen=True)
class Base:
    payments: tuple[int, ...]
    create: int | None
    approval: int | None
    start: int | None


def base_info(activities: tuple[str, ...]) -> Base:
    if any(not isinstance(a, str) or not a for a in activities):
        raise Unsupported("A complete string-valued activity projection is required")
    payments, create, approval, start = [], None, None, None
    for i, activity in enumerate(activities):
        if activity == "Payment":
            payments.append(i)
        elif activity == "Create Fine" and create is None:
            create = i
        if activity in APPROVALS and approval is None:
            approval = i
        if activity == "Start trip" and start is None:
            start = i
    return Base(tuple(payments), create, approval, start)


def base_decision(base: Base, contract: str) -> str | None:
    if contract in TRAFFIC_CONTRACTS:
        if not base.payments:
            return "nonapplicable"
        if base.create is None or base.create > base.payments[0]:
            return "unsupported"
    elif contract == "travel_first_approval":
        if base.start is None:
            return "nonapplicable"
        if base.approval is None:
            return "fail"
    else:
        raise ValueError(contract)
    return None


def dumps(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


@dataclass
class Record:
    case_id: str
    activities: tuple[str, ...]
    contract: str
    granularity: str
    _blocks: dict[str, dict]
    _wire: dict[str, bytes]


def prepare_record(case_id: str, events: list[dict], contract: str, granularity: str) -> Record:
    if granularity not in ("coarse", "fine") or contract not in CONTRACTS:
        raise ValueError((contract, granularity))
    activities = tuple(e.get("concept:name") for e in events)
    base = base_info(activities)
    blocks = {}
    if contract in TRAFFIC_CONTRACTS:
        initial = ({"totalPaymentAmount": events[base.create].get("totalPaymentAmount")}
                   if base.create is not None else None)
        payments = []
        for row, index in enumerate(base.payments):
            event = events[index]
            payload = {"paymentAmount": event.get("paymentAmount")}
            if contract != "traffic_final" or row == len(base.payments) - 1:
                payload["totalPaymentAmount"] = event.get("totalPaymentAmount")
            payments.append(payload)
        if granularity == "coarse":
            blocks["amounts"] = {"initial": initial, "payments": payments}
        else:
            if initial is not None:
                blocks["initial"] = initial
            blocks.update((f"payment/{i}", value) for i, value in enumerate(payments))
        if contract == "traffic_timestamp_groups":
            times = [{"time:timestamp": events[i].get("time:timestamp")} for i in base.payments]
            if granularity == "coarse":
                blocks["payment_times"] = {"payments": times}
            else:
                blocks.update((f"payment_time/{i}", value) for i, value in enumerate(times))
    else:
        times = {}
        for key, index in (("approval", base.approval), ("planned_start", base.start)):
            if index is not None:
                times[key] = {"time:timestamp": events[index].get("time:timestamp")}
        blocks = {"times": times} if granularity == "coarse" else times
    return Record(case_id, activities, contract, granularity, blocks, {k: dumps(v) for k, v in blocks.items()})


class Reader:
    """Only this operation obtains hidden block contents; cache is per decision."""
    __slots__ = ("record", "mode", "cache", "queries", "bytes", "trace")

    def __init__(self, record: Record, mode: str, trace: bool):
        if mode not in ("cached", "json"):
            raise ValueError(mode)
        self.record, self.mode = record, mode
        self.cache, self.queries, self.bytes = {}, 0, 0
        self.trace = [] if trace else None

    def get(self, key: str) -> dict:
        if key not in self.cache:
            wire = self.record._wire[key]
            self.cache[key] = self.record._blocks[key] if self.mode == "cached" else json.loads(wire)
            self.queries += 1
            self.bytes += len(wire)
            if self.trace is not None:
                self.trace.append(key)
        return self.cache[key]


def initial_payload(reader: Reader) -> dict:
    return reader.get("amounts")["initial"] if reader.record.granularity == "coarse" else reader.get("initial")


def payment_payload(reader: Reader, i: int) -> dict:
    return reader.get("amounts")["payments"][i] if reader.record.granularity == "coarse" else reader.get(f"payment/{i}")


def payment_time(reader: Reader, i: int) -> tuple[int, str]:
    value = (reader.get("payment_times")["payments"][i] if reader.record.granularity == "coarse"
             else reader.get(f"payment_time/{i}"))
    return clock(value["time:timestamp"])


def trip_time(reader: Reader, key: str) -> tuple[int, str]:
    value = reader.get("times")[key] if reader.record.granularity == "coarse" else reader.get(key)
    return clock(value["time:timestamp"])


def direct_predicate(reader: Reader, base: Base) -> str:
    """Single evaluation shared by eager acquisition and the manual guard plan."""
    if (known := base_decision(base, reader.record.contract)) is not None:
        return known
    contract = reader.record.contract
    if contract == "travel_first_approval":
        return "pass" if trip_time(reader, "approval") <= trip_time(reader, "planned_start") else "fail"
    cumulative = number(initial_payload(reader)["totalPaymentAmount"])
    if contract == "traffic_timestamp_groups":
        groups = {}
        for i in range(len(base.payments)):
            p = payment_payload(reader, i)
            stamp = payment_time(reader, i)
            amount, total = number(p["paymentAmount"]), number(p["totalPaymentAmount"])
            if stamp not in groups:
                groups[stamp] = [amount, total]
            else:
                groups[stamp][0] += amount
                groups[stamp][1] = max(groups[stamp][1], total)
        for stamp in sorted(groups):
            amount, total = groups[stamp]
            cumulative += amount
            if cumulative != total:
                return "fail"
        return "pass"
    for i in range(len(base.payments)):
        p = payment_payload(reader, i)
        cumulative += number(p["paymentAmount"])
        if contract == "traffic_final" and i < len(base.payments) - 1:
            continue
        total = number(p["totalPaymentAmount"])
        if cumulative != total:
            return "fail"
        if contract == "traffic_recorded_recurrence":
            cumulative = total
    return "pass"


@dataclass(frozen=True)
class Atom:
    name: str
    blocks: tuple[str, ...]
    evaluate: Callable[[Reader, dict], bool]


def compile_atoms(base: Base, record: Record) -> list[Atom]:
    """Compile only visible projection/contract, without opening metadata blocks."""
    coarse = record.granularity == "coarse"
    if record.contract == "travel_first_approval":
        return [Atom("first_approval_le_planned_start", ("times",) if coarse else ("approval", "planned_start"),
                     lambda r, state: trip_time(r, "approval") <= trip_time(r, "planned_start"))]
    if record.contract in ("traffic_final", "traffic_timestamp_groups"):
        if coarse:
            dependencies = ("amounts", "payment_times") if record.contract == "traffic_timestamp_groups" else ("amounts",)
        else:
            dependencies = ("initial",) + tuple(f"payment/{i}" for i in range(len(base.payments)))
            if record.contract == "traffic_timestamp_groups":
                dependencies += tuple(f"payment_time/{i}" for i in range(len(base.payments)))
        return [Atom(record.contract, dependencies, lambda r, state: direct_predicate(r, base) == "pass")]
    atoms = []
    for i in range(len(base.payments)):
        def step(reader: Reader, state: dict, index=i) -> bool:
            if index == 0:
                state["cumulative"] = number(initial_payload(reader)["totalPaymentAmount"])
            p = payment_payload(reader, index)
            state["cumulative"] += number(p["paymentAmount"])
            total = number(p["totalPaymentAmount"])
            result = state["cumulative"] == total
            if record.contract == "traffic_recorded_recurrence":
                state["cumulative"] = total
            return result
        dependencies = (("amounts",) if coarse else
                        (("initial", f"payment/{i}") if i == 0 else (f"payment/{i}",)))
        atoms.append(Atom(f"cumulative_payment_{i}", dependencies, step))
    return atoms


def certificate_plan(reader: Reader, base: Base) -> tuple[str, int, str]:
    if (known := base_decision(base, reader.record.contract)) is not None:
        return known, 0, "activity_projection"
    state, checked = {}, 0
    for atom in compile_atoms(base, reader.record):
        # A missing dependency means the atom is UNKNOWN. Fetch its declared
        # blocks; TRUE advances the conjunction, FALSE certifies its negation.
        for block in atom.blocks:
            if block not in reader.cache:
                reader.get(block)
        checked += 1
        if not atom.evaluate(reader, state):
            return "fail", checked, atom.name
    return "pass", checked, "all_atoms_true"


@dataclass(frozen=True)
class Decision:
    outcome: str
    queries: int
    bytes: int
    trace: tuple[str, ...]
    certificate: str
    atoms_checked: int


def evaluate(record: Record, policy: str, mode: str = "cached", audit: bool = False) -> Decision:
    if policy not in POLICIES:
        raise ValueError(policy)
    reader = Reader(record, mode, audit)
    checked, certificate = 0, "direct_evaluation"
    try:
        base = base_info(record.activities)
        if policy == "full_once":
            for key in record._wire:
                reader.get(key)
            outcome = direct_predicate(reader, base)
        elif policy == "hand_guard":
            outcome = direct_predicate(reader, base)
        else:
            outcome, checked, certificate = certificate_plan(reader, base)
    except (Unsupported, KeyError, TypeError) as exc:
        outcome, certificate = "unsupported", type(exc).__name__
    return Decision(outcome, reader.queries, reader.bytes, tuple(reader.trace or ()), certificate, checked)
