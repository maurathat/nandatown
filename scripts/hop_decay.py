# SPDX-License-Identifier: Apache-2.0
"""Lost in Handoff — offline hop-decay classifier.

Best-of-both merged analyzer:

- authoritative send->receive pairing by per-send correlation IDs;
- multi-hop reconstruction by agent-local event order, because each send mints a
  fresh correlation ID rather than propagating one across the whole chain;
- strict T1 on field-located JSON pointers only;
- explicit denominator exclusions and spread across traces;
- hard failure on vacuous receive-without-send traces.

Example:

    python scripts/hop_decay.py traces/lost_in_handoff.jsonl --rounds 5
    python scripts/hop_decay.py traces/seed*.jsonl --rounds 5 --json
"""

from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from statistics import mean
from typing import Any


CORE_FIELDS = ("card_id", "capability", "rate_usd", "unit", "issued")
POINTER_FIELDS = ("prev", "parent", "ancestor", "derived_from")
FIELD_VALUE_RE = r'"(?P<name>[^"]+)"\s*:\s*(?P<value>"(?:\\.|[^"\\])*"|null|true|false|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'


class TraceStructureError(RuntimeError):
    """Raised when a trace shape would otherwise yield a vacuous green result."""


@dataclass(frozen=True)
class Event:
    index: int
    kind: str
    agent: str
    corr: str | None
    ts: float
    msg: str
    sender: str | None = None
    target: str | None = None


@dataclass(frozen=True)
class Hop:
    hop: int
    trace: str
    receiver: str
    sender: str
    inbound_corr: str | None
    outbound_corr: str | None
    inbound: str
    outbound: str


def load_events(path: Path) -> list[Event]:
    """Load only send/receive events while preserving file order."""
    events: list[Event] = []
    with path.open() as handle:
        for index, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = str(rec.get("kind", ""))
            if kind not in {"send", "receive"}:
                continue
            events.append(
                Event(
                    index=index,
                    kind=kind,
                    agent=str(rec.get("agent", "")),
                    corr=str(rec["corr"]) if rec.get("corr") is not None else None,
                    ts=float(rec.get("ts", 0.0) or 0.0),
                    msg=str(rec.get("msg", "")),
                    sender=str(rec["from"]) if rec.get("from") is not None else None,
                    target=str(rec["to"]) if rec.get("to") is not None else None,
                )
            )
    return events


def extract_json_object(text: str) -> str | None:
    """Return the first balanced JSON object substring from text, if any."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    return None


def looks_truncated(text: str) -> bool:
    """Return True when the payload looks like a cut-off JSON object."""
    return "{" in text and extract_json_object(text) is None


def parse_card(text: str) -> tuple[dict[str, Any], str] | tuple[None, None]:
    """Parse a facts card and return both object and raw JSON substring."""
    raw = extract_json_object(text.strip())
    if raw is None:
        return None, None
    try:
        obj = json.loads(raw, parse_float=Decimal, parse_int=Decimal)
    except (json.JSONDecodeError, ValueError):
        return None, None
    if not isinstance(obj, dict):
        return None, None
    return obj, raw


def raw_field_lexemes(raw_json: str) -> dict[str, str]:
    """Return raw JSON value lexemes by field name."""
    result: dict[str, str] = {}
    for match in re.finditer(FIELD_VALUE_RE, raw_json):
        result[match.group("name")] = match.group("value")
    return result


def _norm(value: Any, form: str) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize(form, value)
    return value


def core_equal(a: dict[str, Any], b: dict[str, Any], form: str = "NFC") -> bool:
    """Return True when every identity-core field matches under *form*."""
    for field in CORE_FIELDS:
        if field not in a or field not in b:
            return False
        av, bv = a[field], b[field]
        if isinstance(av, Decimal) and isinstance(bv, Decimal):
            if av != bv:
                return False
            continue
        if _norm(av, form) != _norm(bv, form):
            return False
    return True


def core_byte_identical(raw_a: str, raw_b: str) -> bool:
    """Return True when raw JSON lexemes for the core fields match exactly."""
    lex_a = raw_field_lexemes(raw_a)
    lex_b = raw_field_lexemes(raw_b)
    for field in CORE_FIELDS:
        if lex_a.get(field) != lex_b.get(field):
            return False
    return True


def strict_pointer(inbound: dict[str, Any], outbound: dict[str, Any]) -> bool:
    """Return True for T1-strict field-located pointers only."""
    card_id = inbound.get("card_id")
    if card_id is None:
        return False
    card_id_s = str(card_id)
    for field in POINTER_FIELDS:
        if str(outbound.get(field, "")) == card_id_s:
            return True
    return str(outbound.get("card_id", "")) == card_id_s


def substring_pointer_diag(inbound: dict[str, Any], raw_outbound: str) -> bool:
    """Return True when the inbound card id only appears as a bare substring."""
    card_id = inbound.get("card_id")
    if card_id is None:
        return False
    return str(card_id) in raw_outbound


def classify(inbound_raw: str, outbound_raw: str) -> dict[str, Any]:
    """Classify one hop as T0, T1, T2, or UNSCORED."""
    inbound_card, inbound_json = parse_card(inbound_raw)
    if inbound_card is None or inbound_json is None:
        return {"tier": "UNSCORED", "reason": "inbound-not-a-card"}

    if looks_truncated(outbound_raw):
        return {"tier": "UNSCORED", "reason": "outbound-truncated"}

    outbound_card, outbound_json = parse_card(outbound_raw)
    if outbound_card is None or outbound_json is None:
        return {
            "tier": "T2",
            "reason": "outbound-not-a-card",
            "payload_byte_identical": False,
            "core_byte_identical": False,
            "nfkc_only": False,
            "substring_ptr_diag": substring_pointer_diag(inbound_card, outbound_raw),
        }

    if core_equal(inbound_card, outbound_card, "NFC"):
        return {
            "tier": "T0",
            "payload_byte_identical": inbound_json == outbound_json,
            "core_byte_identical": core_byte_identical(inbound_json, outbound_json),
            "nfkc_only": False,
            "substring_ptr_diag": False,
        }

    if core_equal(inbound_card, outbound_card, "NFKC"):
        return {
            "tier": "T2",
            "payload_byte_identical": False,
            "core_byte_identical": False,
            "nfkc_only": True,
            "substring_ptr_diag": False,
        }

    tier = "T1" if strict_pointer(inbound_card, outbound_card) else "T2"
    return {
        "tier": tier,
        "payload_byte_identical": False,
        "core_byte_identical": False,
        "nfkc_only": False,
        "substring_ptr_diag": False,
    }


def _next_send_for_receive(receive: Event, agent_events: list[Event]) -> Event | None:
    """Return the first send after a receive, unless another receive intervenes."""
    seen_receive = False
    for event in agent_events:
        if event.index < receive.index:
            continue
        if event.index == receive.index:
            seen_receive = True
            continue
        if not seen_receive:
            continue
        if event.kind == "receive":
            return None
        if event.kind == "send":
            return event
    return None


def build_trace(path: Path, rounds: int) -> dict[str, Any]:
    """Reconstruct hops and denominator exclusions for one trace.

    Correlation IDs are authoritative for one send->receive edge only. Each
    outbound send mints a fresh correlation ID, so multi-hop reconstruction
    chains `receive -> next send by the same agent -> matching receive by corr`.
    """
    events = load_events(path)
    send_events = [event for event in events if event.kind == "send"]
    receive_events = [event for event in events if event.kind == "receive"]

    counts = {"send": len(send_events), "receive": len(receive_events)}
    if counts["receive"] > 0 and counts["send"] == 0:
        raise TraceStructureError(
            f"{path}: receive_count={counts['receive']}, send_count=0; "
            "refusing vacuous zero-hop result"
        )

    receives_by_corr = {
        event.corr: event for event in receive_events if event.corr is not None
    }

    by_agent: dict[str, list[Event]] = defaultdict(list)
    prior_receive_count: dict[int, int] = {}
    receive_ordinal: dict[int, int] = {}
    receive_count_by_agent: dict[str, int] = defaultdict(int)
    for event in events:
        by_agent[event.agent].append(event)
        prior_receive_count[event.index] = receive_count_by_agent[event.agent]
        if event.kind == "receive":
            receive_count_by_agent[event.agent] += 1
            receive_ordinal[event.index] = receive_count_by_agent[event.agent]

    response_send_by_receive: dict[int, Event] = {}
    for event in receive_events:
        response = _next_send_for_receive(event, by_agent[event.agent])
        if response is not None:
            response_send_by_receive[event.index] = response

    origin_sends = [event for event in send_events if prior_receive_count.get(event.index, 0) == 0]
    hops: list[Hop] = []
    for origin in origin_sends:
        receive = receives_by_corr.get(origin.corr)
        if receive is None:
            continue
        depth = 1
        seen_receives: set[int] = set()
        current = receive
        while current.index not in seen_receives:
            seen_receives.add(current.index)
            outbound = response_send_by_receive.get(current.index)
            if outbound is None:
                break
            hops.append(
                Hop(
                    hop=depth,
                    trace=str(path),
                    receiver=current.agent,
                    sender=current.sender or "",
                    inbound_corr=current.corr,
                    outbound_corr=outbound.corr,
                    inbound=current.msg,
                    outbound=outbound.msg,
                )
            )
            next_receive = receives_by_corr.get(outbound.corr)
            if next_receive is None:
                break
            current = next_receive
            depth += 1

    no_outbound = 0
    no_outbound_round_cap = 0
    for receive in receive_events:
        if receive.index in response_send_by_receive:
            continue
        if receive_ordinal.get(receive.index, 0) > rounds:
            no_outbound_round_cap += 1
        else:
            no_outbound += 1

    return {
        "events": events,
        "counts": counts,
        "originations": len(origin_sends),
        "hops": hops,
        "no_outbound": no_outbound,
        "no_outbound_round_cap": no_outbound_round_cap,
    }


def _rate(rows: list[dict[str, Any]], tier: str) -> float | None:
    scored = [row for row in rows if row["tier"] != "UNSCORED"]
    if not scored:
        return None
    return sum(1 for row in scored if row["tier"] == tier) / len(scored)


def _spread(values: list[float | None]) -> dict[str, float | None]:
    concrete = [value for value in values if value is not None]
    if not concrete:
        return {"mean": None, "min": None, "max": None}
    return {"mean": mean(concrete), "min": min(concrete), "max": max(concrete)}


def analyze(paths: list[Path], rounds: int) -> dict[str, Any]:
    """Analyze one or more traces and aggregate per-hop results."""
    per_trace: list[dict[str, Any]] = []
    by_hop_overall: dict[int, list[dict[str, Any]]] = defaultdict(list)
    by_hop_trace: dict[int, list[list[dict[str, Any]]]] = defaultdict(list)
    excluded = {"originations": 0, "no_outbound": 0, "no_outbound_round_cap": 0}

    for path in paths:
        built = build_trace(path, rounds)
        rows = [{**hop.__dict__, **classify(hop.inbound, hop.outbound)} for hop in built["hops"]]
        grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            hop_number = int(row["hop"])
            grouped[hop_number].append(row)
            by_hop_overall[hop_number].append(row)
        for hop_number, hop_rows in grouped.items():
            by_hop_trace[hop_number].append(hop_rows)

        for key in excluded:
            excluded[key] += int(built[key])

        per_trace.append(
            {
                "trace": str(path),
                "send_events": built["counts"]["send"],
                "receive_events": built["counts"]["receive"],
                "originations": built["originations"],
                "no_outbound": built["no_outbound"],
                "no_outbound_round_cap": built["no_outbound_round_cap"],
                "hops": [
                    {
                        "hop": hop_number,
                        "n_total": len(hop_rows),
                        "n_scored": sum(1 for row in hop_rows if row["tier"] != "UNSCORED"),
                        "n_unscored": sum(1 for row in hop_rows if row["tier"] == "UNSCORED"),
                        "T0_rate": _rate(hop_rows, "T0"),
                        "T1_rate": _rate(hop_rows, "T1"),
                        "T2_rate": _rate(hop_rows, "T2"),
                    }
                    for hop_number, hop_rows in sorted(grouped.items())
                ],
            }
        )

    per_hop: list[dict[str, Any]] = []
    for hop_number in sorted(by_hop_overall):
        rows = by_hop_overall[hop_number]
        scored = [row for row in rows if row["tier"] != "UNSCORED"]
        trace_rows = by_hop_trace[hop_number]
        unscored_reasons = Counter(
            str(row.get("reason"))
            for row in rows
            if row["tier"] == "UNSCORED"
        )
        per_hop.append(
            {
                "hop": hop_number,
                "n_total": len(rows),
                "n_scored": len(scored),
                "n_unscored": len(rows) - len(scored),
                "T0": sum(1 for row in scored if row["tier"] == "T0"),
                "T1": sum(1 for row in scored if row["tier"] == "T1"),
                "T2": sum(1 for row in scored if row["tier"] == "T2"),
                "T0_payload_byte_identical": sum(
                    1 for row in scored if row["tier"] == "T0" and row.get("payload_byte_identical")
                ),
                "T0_payload_byte_different": sum(
                    1 for row in scored if row["tier"] == "T0" and not row.get("payload_byte_identical")
                ),
                "T0_core_byte_identical": sum(
                    1 for row in scored if row["tier"] == "T0" and row.get("core_byte_identical")
                ),
                "T0_core_byte_different": sum(
                    1 for row in scored if row["tier"] == "T0" and not row.get("core_byte_identical")
                ),
                "nfkc_only_diag": sum(1 for row in scored if row.get("nfkc_only")),
                "T1_substring_diag": sum(1 for row in scored if row.get("substring_ptr_diag")),
                "unscored_reasons": dict(sorted(unscored_reasons.items())),
                "spread": {
                    "T0_rate": _spread([_rate(hop_rows, "T0") for hop_rows in trace_rows]),
                    "T1_rate": _spread([_rate(hop_rows, "T1") for hop_rows in trace_rows]),
                    "T2_rate": _spread([_rate(hop_rows, "T2") for hop_rows in trace_rows]),
                },
            }
        )

    return {
        "meta": {
            "identity_function": "handoff-core/1",
            "corr_scope": "per-send edge only; each send mints a fresh corr id",
            "rounds": rounds,
        },
        "traces": per_trace,
        "per_hop": per_hop,
        "excluded": excluded,
    }


def _fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _print_text(report: dict[str, Any]) -> None:
    meta = report["meta"]
    print(
        "Lost in Handoff — hop decay "
        f"[identity={meta['identity_function']}, corr={meta['corr_scope']}]"
    )
    print(f"traces: {len(report['traces'])}")
    for trace in report["traces"]:
        print(
            f"  {trace['trace']}: send={trace['send_events']} receive={trace['receive_events']} "
            f"originations={trace['originations']} no_outbound={trace['no_outbound']} "
            f"round_cap={trace['no_outbound_round_cap']}"
        )
        if not trace["hops"]:
            print("    hops: 0")
        for row in trace["hops"]:
            print(
                f"    hop {row['hop']}: total={row['n_total']} scored={row['n_scored']} "
                f"unscored={row['n_unscored']} T0={_fmt_rate(row['T0_rate'])} "
                f"T1={_fmt_rate(row['T1_rate'])} T2={_fmt_rate(row['T2_rate'])}"
            )

    ex = report["excluded"]
    print(
        "\nexcluded from denominator: "
        f"originations={ex['originations']} "
        f"no_outbound={ex['no_outbound']} "
        f"no_outbound_round_cap={ex['no_outbound_round_cap']}"
    )

    if not report["per_hop"]:
        print("\nNo scored hops found.")
        return

    print("\nAggregated per hop")
    print("hop  total  scored  unscored  T0  T1  T2  T0_mean  T1_mean  T2_mean  T0_core_byte_diff  substring_diag")
    for row in report["per_hop"]:
        print(
            f"{row['hop']:<4} {row['n_total']:<6} {row['n_scored']:<7} {row['n_unscored']:<9} "
            f"{row['T0']:<3} {row['T1']:<3} {row['T2']:<3} "
            f"{_fmt_rate(row['spread']['T0_rate']['mean']):<8} "
            f"{_fmt_rate(row['spread']['T1_rate']['mean']):<8} "
            f"{_fmt_rate(row['spread']['T2_rate']['mean']):<8} "
            f"{row['T0_core_byte_different']:<17} {row['T1_substring_diag']}"
        )
        print(f"  hop {row['hop']} unscored_count={row['n_unscored']}")
        if row["nfkc_only_diag"]:
            print(f"  hop {row['hop']} NFKC-only diagnostics: {row['nfkc_only_diag']}")
        if row["unscored_reasons"]:
            reasons = ", ".join(f"{reason}={count}" for reason, count in row["unscored_reasons"].items())
            print(f"  hop {row['hop']} unscored reasons: {reasons}")
        for tier in ("T0_rate", "T1_rate", "T2_rate"):
            spread = row["spread"][tier]
            if spread["mean"] is not None:
                print(
                    f"  hop {row['hop']} {tier}: "
                    f"mean={spread['mean']:.3f} min={spread['min']:.3f} max={spread['max']:.3f}"
                )


def main() -> None:
    parser = argparse.ArgumentParser(description="Lost in Handoff — hop-decay classifier")
    parser.add_argument("traces", nargs="+", type=Path)
    parser.add_argument(
        "--rounds",
        type=int,
        default=5,
        help="scenario task.config.rounds; separates round-cap artifacts from real no-outbound cases",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()

    try:
        report = analyze(list(args.traces), args.rounds)
    except TraceStructureError as exc:
        raise SystemExit(str(exc)) from exc

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return
    _print_text(report)


if __name__ == "__main__":
    main()
