"""Independent raw-event reference implementation for authored external rules.

It does not import the production parser, projection adapter or policy code.
Numerics use Decimal with an exact sufficient precision; times use datetime
plus rational subseconds, unlike the production integer/string ordering key.
"""
from collections import defaultdict
from datetime import datetime
from decimal import Decimal, InvalidOperation, localcontext
from fractions import Fraction
import re


def _numeric(text):
    if not isinstance(text, str) or not text.isascii() or not re.fullmatch(
        r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", text
    ):
        raise ValueError("unsupported numeric lexeme")
    value = Decimal(text)
    if not value.is_finite():
        raise ValueError("nonfinite numeric value")
    return value


def _time(text):
    if not isinstance(text, str) or not text.isascii() or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})", text
    ) or text.endswith("-00:00"):
        raise ValueError("unsupported timestamp")
    # datetime can normalize some invalid offsets; explicitly exclude them.
    if text[-1] not in "Zz" and (int(text[-5:-3]) > 23 or int(text[-2:]) > 59):
        raise ValueError("offset out of range")
    fraction_match = re.search(r"\.([0-9]+)", text)
    fraction = Fraction(0)
    whole_text = text
    if fraction_match:
        digits = fraction_match.group(1)
        fraction = Fraction(int(digits), 10 ** len(digits))
        whole_text = text[:fraction_match.start()] + text[fraction_match.end():]
    if whole_text[-1] in "Zz":
        whole_text = whole_text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(whole_text)
    # Subtract the offset numerically: astimezone would overflow when a valid
    # year-0001/9999 local time normalizes beyond datetime's representable years.
    delta = parsed.replace(tzinfo=None) - datetime(1970, 1, 1)
    offset = parsed.utcoffset()
    return Fraction(delta.days * 86400 + delta.seconds - offset.days * 86400 - offset.seconds) + fraction


def _precision(values, terms):
    lowest = min(v.as_tuple().exponent for v in values)
    highest = max(v.adjusted() for v in values)
    return max(28, highest - lowest + len(str(terms + 1)) + 5)


def direct_oracle(events, contract):
    """Validate relevant input domain, then compute one raw-event label.

The domain check is intentionally exhaustive. Short-circuit certificates are
only guaranteed to agree on this valid domain, not on unseen malformed data.
"""
    try:
        names = [event.get("concept:name") for event in events]
        if any(not isinstance(name, str) or not name for name in names):
            return "unsupported"
        if contract == "travel_first_approval":
            starts = [i for i, name in enumerate(names) if name == "Start trip"]
            if not starts:
                return "nonapplicable"
            approvals = [i for i, name in enumerate(names) if name in (
                "Permit FINAL_APPROVED by SUPERVISOR", "Permit FINAL_APPROVED by DIRECTOR")]
            if not approvals:
                return "fail"
            approval = _time(events[approvals[0]].get("time:timestamp"))
            planned_start = _time(events[starts[0]].get("time:timestamp"))
            return "pass" if approval <= planned_start else "fail"
        payments = [event for event in events if event.get("concept:name") == "Payment"]
        if not payments:
            return "nonapplicable"
        creates = [i for i, name in enumerate(names) if name == "Create Fine"]
        if not creates or creates[0] > names.index("Payment"):
            return "unsupported"
        initial = _numeric(events[creates[0]].get("totalPaymentAmount"))
        amounts = [_numeric(event.get("paymentAmount")) for event in payments]
        if contract == "traffic_final":
            # Intermediate totals are irrelevant to this predicate's domain.
            totals = [_numeric(payments[-1].get("totalPaymentAmount"))]
        else:
            totals = [_numeric(event.get("totalPaymentAmount")) for event in payments]
        values = [initial] + amounts + totals
        with localcontext() as context:
            context.prec = _precision(values, len(payments))
            if contract == "traffic_final":
                return "pass" if initial + sum(amounts) == totals[-1] else "fail"
            if contract == "traffic_timestamp_groups":
                groups = defaultdict(list)
                for event, amount, total in zip(payments, amounts, totals):
                    groups[_time(event.get("time:timestamp"))].append((amount, total))
                running = initial
                answers = []
                for instant in sorted(groups):
                    group = groups[instant]
                    running += sum(amount for amount, _ in group)
                    answers.append(running == max(total for _, total in group))
                return "pass" if all(answers) else "fail"
            if contract == "traffic_cumulative":
                answers = [initial + sum(amounts[:i + 1]) == total for i, total in enumerate(totals)]
                return "pass" if all(answers) else "fail"
            if contract == "traffic_recorded_recurrence":
                previous = [initial] + totals[:-1]
                return "pass" if all(p + a == t for p, a, t in zip(previous, amounts, totals)) else "fail"
            raise ValueError(contract)
    except (ValueError, TypeError, KeyError, InvalidOperation, OverflowError):
        return "unsupported"
