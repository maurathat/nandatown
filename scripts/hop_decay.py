# SPDX-License-Identifier: Apache-2.0
"""Lost in Handoff — offline hop-decay classifier.

Reads one or more scenario traces and reports, per hop, what fraction of facts
cards arrive with their identity core intact.

No runtime instrumentation: the simulator already records full payload text on
every ``receive`` record (nest_core/sim/simulator.py:358-369).

=============================================================================
PRE-REGISTERED SPEC — fix before running; changes after a run are amendments
=============================================================================

IDENTITY FUNCTION: ``handoff-core/1``
    Core fields, in order: card_id, capability, rate_usd, unit, issued.
    - String fields compare under Unicode **NFC**. No case folding, no
      whitespace trimming, no punctuation folding.
    - Numeric fields parse to ``Decimal``. CONTENT equality is numeric
      (``1234.50 == 1234.5``). BYTE equality is ``str(Decimal)`` identity,
      which preserves trailing zeros.
    - A core field absent on either side is a MISMATCH, never a pass.
    - ``hops`` and ``prev`` are bookkeeping and excluded from identity.
    - JSON key order and whitespace outside field values are NOT part of
      identity. That exclusion is the structural claim being tested.
    - This is deliberately NOT JCS/``jcs1``. That ruleset is a separate,
      blocked workstream. ``handoff-core/1`` compares field-wise over a fixed
      core rather than canonicalizing the whole object.

TIERS
    T0  every core field content-equal under handoff-core/1.
        Sub-case ``byte_identical``: also identical character-for-character.
        T0-with-differing-bytes is exactly what a byte checksum misses.
    T1  STRICT and field-located only: outbound parses as a JSON object AND
        (``outbound.prev == inbound.card_id`` OR
         ``outbound.card_id == inbound.card_id``), compared as exact strings.
        Resolution scope: the pointer must equal the card_id of THAT hop's
        inbound document, which is by construction present in the trace, so
        the pointer resolves within the run. No external resolution is
        attempted. A bare card_id appearing in non-JSON prose does NOT count
        as T1; it is reported as ``T1_substring_diag``, keeping the headline
        conservative.
    T2  neither holds.

HOP PAIRING
    Per agent, outbounds are walked in timestamp order and each is paired with
    the LATEST still-unpaired inbound strictly preceding it. Pairing is
    one-to-one: an outbound is consumed by at most one inbound. An outbound
    with no preceding inbound is an ORIGINATION (hop 0), not a hop.

DENOMINATOR
    Scored hops are paired inbound->outbound transitions where the inbound
    parses as a card and the outbound is not truncated. Excluded and reported
    separately, never silently dropped:
    - ``no-outbound``: inbound never relayed. The document stopped. This is
      loss, but a different failure from corrupted relay, so it is reported
      beside the tiers rather than inside them.
    - ``no-outbound-round-cap``: inbound arriving after the agent's round
      budget, where ShellAgent returns early (agent.py:155). A HARNESS
      artifact. Counting it as collapse would fabricate the result.
    - ``outbound-truncated``: backend runs at max_tokens=256 (llm.py:98;
      runner.py:123 passes no override), so truncation is a live confound and
      would otherwise inflate T2.

Example::

    python scripts/hop_decay.py traces/lost_in_handoff.jsonl --rounds 5
    python scripts/hop_decay.py traces/seed*.jsonl --json
"""

from __future__ import annotations

import argparse
import json
import unicodedata
from collections import defaultdict
from decimal import Decimal
from pathlib import Path
from typing import Any

CORE_FIELDS = ("card_id", "capability", "rate_usd", "unit", "issued")
BOOKKEEPING_FIELDS = ("hops", "prev")


def load_receives(path: Path) -> list[dict[str, Any]]:
    """Return ``receive`` records from a trace, preserving file order on ties.

    Example::

        recs = load_receives(Path("traces/lost_in_handoff.jsonl"))
    """
    recs: list[dict[str, Any]] = []
    with path.open() as f:
        for seq, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("kind") == "receive":
                rec["_seq"] = seq
                recs.append(rec)
    recs.sort(key=lambda r: (r.get("ts", 0), r.get("_seq", 0)))
    return recs


def _order_key(rec: dict[str, Any]) -> tuple[Any, Any]:
    """Return a stable ordering key for trace records.

    Example::

        _order_key({"ts": 0.0, "_seq": 7})
    """
    return (rec.get("ts", 0), rec.get("_seq", 0))


def parse_card(text: str) -> dict[str, Any] | None:
    """Parse a single-line JSON facts card, preserving numeric literals.

    Example::

        card = parse_card('{"card_id":"a","rate_usd":1234.50}')
    """
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        obj = json.loads(text[start : end + 1], parse_float=Decimal, parse_int=Decimal)
    except (json.JSONDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def looks_truncated(text: str) -> bool:
    """Return True if the payload appears cut off mid-object.

    Example::

        looks_truncated('{"card_id":"a","capab')
    """
    text = text.strip()
    return "{" in text and text.rfind("}") < text.rfind("{")


def _norm(value: Any, form: str) -> Any:
    """Normalize a scalar for content comparison.

    Example::

        _norm("cafe\\u0301", "NFC")
    """
    if isinstance(value, str):
        return unicodedata.normalize(form, value)
    return value


def core_equal(a: dict[str, Any], b: dict[str, Any], form: str) -> bool:
    """Return True if every identity-core field matches under *form*.

    Example::

        core_equal(inbound, outbound, "NFC")
    """
    for field in CORE_FIELDS:
        if field not in a or field not in b:
            return False
        av, bv = a[field], b[field]
        if isinstance(av, Decimal) and isinstance(bv, Decimal):
            if av != bv:
                return False
        elif _norm(av, form) != _norm(bv, form):
            return False
    return True


def core_byte_identical(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Return True if the core fields are identical character-for-character.

    Example::

        core_byte_identical(inbound, outbound)
    """
    for field in CORE_FIELDS:
        if field not in a or field not in b:
            return False
        if str(a[field]) != str(b[field]):
            return False
    return True


def strict_pointer(inbound: dict[str, Any], outbound: dict[str, Any]) -> bool:
    """Return True if *outbound* field-locates the inbound card_id (T1-strict).

    Example::

        strict_pointer({"card_id": "x"}, {"prev": "x"})
    """
    cid = inbound.get("card_id")
    if cid is None:
        return False
    cid_s = str(cid)
    return str(outbound.get("prev", "")) == cid_s or str(outbound.get("card_id", "")) == cid_s


def classify(inbound_raw: str, outbound_raw: str) -> dict[str, Any]:
    """Classify one hop: inbound document -> outbound document.

    Example::

        classify('{"card_id":"a"}', '{"card_id":"a"}')
    """
    in_card = parse_card(inbound_raw)
    if in_card is None:
        return {"tier": "UNSCORED", "reason": "inbound-not-a-card"}

    if looks_truncated(outbound_raw):
        return {"tier": "UNSCORED", "reason": "outbound-truncated"}

    out_card = parse_card(outbound_raw)
    if out_card is None:
        cid = str(in_card.get("card_id", "\x00"))
        return {
            "tier": "T2",
            "reason": "outbound-not-json",
            "byte_identical": False,
            "substring_ptr": cid in outbound_raw,
        }

    if core_equal(in_card, out_card, "NFC"):
        return {
            "tier": "T0",
            "byte_identical": core_byte_identical(in_card, out_card),
            "nfkc_only": False,
            "substring_ptr": False,
        }

    # Failed NFC, passes NFKC: a compatibility re-encode (e.g. MICRO SIGN
    # U+00B5 swapped for GREEK SMALL LETTER MU U+03BC). Diagnostic only --
    # NOT folded into T0, because T0 is defined on NFC.
    nfkc_only = core_equal(in_card, out_card, "NFKC")

    tier = "T1" if strict_pointer(in_card, out_card) else "T2"
    return {
        "tier": tier,
        "byte_identical": False,
        "nfkc_only": nfkc_only,
        "substring_ptr": False,
    }


def build_hops(recs: list[dict[str, Any]], rounds: int) -> dict[str, Any]:
    """Pair inbound documents with the outbound each agent then produced.

    One-to-one, latest-preceding-inbound, per the pre-registered spec.

    Example::

        result = build_hops(load_receives(path), rounds=5)
    """
    inbound_by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    outbound_by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in recs:
        inbound_by_agent[str(r.get("agent"))].append(r)
        outbound_by_agent[str(r.get("from"))].append(r)

    pair_of: dict[int, dict[str, Any]] = {}
    originations: list[dict[str, Any]] = []
    unrelayed: list[dict[str, Any]] = []

    for agent, outs in outbound_by_agent.items():
        ins = sorted(inbound_by_agent.get(agent, []), key=_order_key)
        used: set[int] = set()
        for out in sorted(outs, key=_order_key):
            cand = [i for i in ins if _order_key(i) < _order_key(out) and id(i) not in used]
            if not cand:
                originations.append(out)
                continue
            chosen = cand[-1]
            used.add(id(chosen))
            pair_of[id(chosen)] = out
        for idx, i in enumerate(ins, start=1):
            if id(i) not in used:
                unrelayed.append({"rec": i, "index_at_agent": idx})

    # Agents that never sent anything still hold unrelayed inbounds.
    for agent, ins_all in inbound_by_agent.items():
        if agent in outbound_by_agent:
            continue
        for idx, i in enumerate(sorted(ins_all, key=lambda r: r.get("ts", 0)), start=1):
            unrelayed.append({"rec": i, "index_at_agent": idx})

    hops: list[dict[str, Any]] = []
    for origin in originations:
        cur, depth, seen = origin, 1, {id(origin)}
        while True:
            nxt = pair_of.get(id(cur))
            if nxt is None or id(nxt) in seen:
                break
            seen.add(id(nxt))
            hops.append(
                {
                    "hop": depth,
                    "at": str(cur.get("agent")),
                    "inbound": str(cur.get("msg", "")),
                    "outbound": str(nxt.get("msg", "")),
                }
            )
            cur, depth = nxt, depth + 1

    no_outbound = sum(1 for u in unrelayed if u["index_at_agent"] <= rounds)
    round_capped = sum(1 for u in unrelayed if u["index_at_agent"] > rounds)
    return {
        "hops": hops,
        "originations": len(originations),
        "no_outbound": no_outbound,
        "no_outbound_round_cap": round_capped,
    }


def analyze(paths: list[Path], rounds: int) -> dict[str, Any]:
    """Classify every hop in every trace and aggregate per hop index.

    Example::

        report = analyze([Path("traces/lost_in_handoff.jsonl")], rounds=5)
    """
    per_trace: list[dict[str, Any]] = []
    per_hop: dict[int, list[dict[str, Any]]] = defaultdict(list)
    excluded = {"no_outbound": 0, "no_outbound_round_cap": 0, "originations": 0}

    for p in paths:
        recs = load_receives(p)
        built = build_hops(recs, rounds)
        results = [{**h, **classify(h["inbound"], h["outbound"])} for h in built["hops"]]
        for r in results:
            per_hop[int(r["hop"])].append(r)
        for k in excluded:
            excluded[k] += int(built[k])
        per_trace.append(
            {
                "trace": str(p),
                "receives": len(recs),
                "hops": len(results),
                "no_outbound": built["no_outbound"],
                "no_outbound_round_cap": built["no_outbound_round_cap"],
            }
        )

    summary: list[dict[str, Any]] = []
    for hop in sorted(per_hop):
        rows = per_hop[hop]
        scored = [r for r in rows if r["tier"] != "UNSCORED"]
        n = len(scored)
        t0 = [r for r in scored if r["tier"] == "T0"]
        summary.append(
            {
                "hop": hop,
                "n_scored": n,
                "n_unscored": len(rows) - n,
                "T0": len(t0),
                "T1": sum(1 for r in scored if r["tier"] == "T1"),
                "T2": sum(1 for r in scored if r["tier"] == "T2"),
                "T0_rate": (len(t0) / n) if n else None,
                "T0_byte_identical": sum(1 for r in t0 if r.get("byte_identical")),
                "T0_byte_different": sum(1 for r in t0 if not r.get("byte_identical")),
                "nfkc_only_diag": sum(1 for r in scored if r.get("nfkc_only")),
                "T1_substring_diag": sum(1 for r in scored if r.get("substring_ptr")),
                "unscored_reasons": sorted(
                    {str(r.get("reason")) for r in rows if r["tier"] == "UNSCORED"}
                ),
            }
        )
    return {"traces": per_trace, "per_hop": summary, "excluded": excluded}


def main() -> None:
    """CLI entry point.

    Example::

        python scripts/hop_decay.py traces/lost_in_handoff.jsonl
    """
    ap = argparse.ArgumentParser(description="Lost in Handoff — hop-decay classifier")
    ap.add_argument("traces", nargs="+", type=Path)
    ap.add_argument(
        "--rounds",
        type=int,
        default=5,
        help="scenario task.config.rounds; separates round-cap artifacts from real loss",
    )
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    report = analyze(list(args.traces), args.rounds)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return

    print("Lost in Handoff — hop decay   [identity fn: handoff-core/1, T0 on NFC]")
    for t in report["traces"]:
        print(
            f"  {t['trace']}: {t['receives']} receives, {t['hops']} hops, "
            f"{t['no_outbound']} unrelayed, {t['no_outbound_round_cap']} round-capped"
        )
    ex = report["excluded"]
    print(
        f"\nexcluded from denominator: {ex['originations']} originations, "
        f"{ex['no_outbound']} no-outbound, {ex['no_outbound_round_cap']} round-cap artifacts"
    )
    if not report["per_hop"]:
        print("\nNo hops found. Nothing to score.")
        return
    print("\nhop  n     T0    T1    T2    T0_rate  T0_bytediff  unscored")
    for row in report["per_hop"]:
        rate = "n/a" if row["T0_rate"] is None else f"{row['T0_rate']:.2f}"
        print(
            f"{row['hop']:<4} {row['n_scored']:<5} {row['T0']:<5} {row['T1']:<5} "
            f"{row['T2']:<5} {rate:<8} {row['T0_byte_different']:<12} {row['n_unscored']}"
        )
    print("\ndiagnostics (not folded into the tiers):")
    for row in report["per_hop"]:
        bits: list[str] = []
        if row["nfkc_only_diag"]:
            bits.append(f"{row['nfkc_only_diag']} NFKC-only re-encode")
        if row["T1_substring_diag"]:
            bits.append(f"{row['T1_substring_diag']} substring-only pointer")
        if row["unscored_reasons"]:
            bits.append("unscored: " + ", ".join(row["unscored_reasons"]))
        if bits:
            print(f"  hop {row['hop']}: {'; '.join(bits)}")


if __name__ == "__main__":
    main()
