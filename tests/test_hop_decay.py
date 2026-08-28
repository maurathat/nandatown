from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "hop_decay.py"
)
SPEC = importlib.util.spec_from_file_location("hop_decay_codex", SCRIPT_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
TRACE_DIR = Path(__file__).resolve().parents[1] / "traces"


def _write_trace(path: Path, events: list[dict[str, object]]) -> Path:
    path.write_text("\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n")
    return path


def test_classify_t0_core_equal_but_byte_different() -> None:
    inbound = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.50,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":0,"prev":null}'
    )
    outbound = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.500,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":1,"prev":"c1"}'
    )
    result = MODULE.classify(inbound, outbound)
    assert result["tier"] == "T0"
    assert result["core_byte_identical"] is False
    assert result["payload_byte_identical"] is False


def test_classify_t1_when_prev_points_to_inbound_card() -> None:
    inbound = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.50,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":0,"prev":null}'
    )
    outbound = (
        '{"card_id":"c2","capability":"Different work","rate_usd":99.00,'
        '"unit":"µs","issued":"2026-08-23T14:03:00Z","hops":1,"prev":"c1"}'
    )
    result = MODULE.classify(inbound, outbound)
    assert result["tier"] == "T1"


def test_classify_non_json_card_id_mention_is_t2_with_diag() -> None:
    inbound = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.50,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":0,"prev":null}'
    )
    outbound = "I saw card c1 and rewrote it in prose."
    result = MODULE.classify(inbound, outbound)
    assert result["tier"] == "T2"
    assert result["substring_ptr_diag"] is True


def test_classify_t2_and_nfkc_only_diagnostic() -> None:
    inbound = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.50,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":0,"prev":null}'
    )
    outbound = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.50,'
        '"unit":"μs","issued":"2026-08-22T14:03:00Z","hops":1,"prev":"c1"}'
    )
    result = MODULE.classify(inbound, outbound)
    assert result["tier"] == "T2"
    assert result["nfkc_only"] is True


def test_build_trace_uses_fresh_corr_per_edge_and_recovers_depth(tmp_path: Path) -> None:
    card0 = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.50,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":0,"prev":null}'
    )
    card1 = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.500,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":1,"prev":"c1"}'
    )
    card2 = (
        '{"card_id":"c2","capability":"Other task","rate_usd":99.00,'
        '"unit":"µs","issued":"2026-08-23T14:03:00Z","hops":2,"prev":"c1"}'
    )
    trace = _write_trace(
        tmp_path / "trace-corr.jsonl",
        [
            {"agent": "buyer-0", "kind": "send", "corr": "c-1", "to": "seller-0", "msg": card0, "ts": 0.0},
            {
                "agent": "seller-0",
                "kind": "receive",
                "corr": "c-1",
                "from": "buyer-0",
                "msg": card0,
                "ts": 0.0,
            },
            {"agent": "seller-0", "kind": "send", "corr": "c-2", "to": "buyer-1", "msg": card1, "ts": 1.0},
            {
                "agent": "buyer-1",
                "kind": "receive",
                "corr": "c-2",
                "from": "seller-0",
                "msg": card1,
                "ts": 1.0,
            },
            {"agent": "buyer-1", "kind": "send", "corr": "c-3", "to": "seller-1", "msg": card2, "ts": 2.0},
            {
                "agent": "seller-1",
                "kind": "receive",
                "corr": "c-3",
                "from": "buyer-1",
                "msg": card2,
                "ts": 2.0,
            },
            {"agent": "seller-1", "kind": "send", "corr": "c-4", "to": "buyer-2", "msg": "not a card", "ts": 3.0},
            {
                "agent": "buyer-2",
                "kind": "receive",
                "corr": "c-4",
                "from": "seller-1",
                "msg": "not a card",
                "ts": 3.0,
            },
        ],
    )

    built = MODULE.build_trace(trace, rounds=5)
    hops = built["hops"]
    assert built["counts"] == {"send": 4, "receive": 4}
    assert [hop.hop for hop in hops] == [1, 2, 3]
    assert hops[0].inbound_corr == "c-1"
    assert hops[0].outbound_corr == "c-2"
    assert hops[1].inbound_corr == "c-2"
    assert hops[1].outbound_corr == "c-3"
    assert hops[2].inbound_corr == "c-3"
    assert hops[2].outbound_corr == "c-4"


def test_build_trace_errors_on_receives_without_sends(tmp_path: Path) -> None:
    trace = _write_trace(
        tmp_path / "bad.jsonl",
        [
            {
                "agent": "seller-0",
                "kind": "receive",
                "corr": "c-1",
                "from": "buyer-0",
                "msg": '{"card_id":"c1"}',
                "ts": 0.0,
            }
        ],
    )
    with pytest.raises(MODULE.TraceStructureError, match="refusing vacuous zero-hop result"):
        MODULE.build_trace(trace, rounds=5)


def test_analyze_reports_spread_and_explicit_zero_unscored(tmp_path: Path) -> None:
    card = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.50,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":0,"prev":null}'
    )
    same = (
        '{"card_id":"c1","capability":"Analyze needs","rate_usd":1234.500,'
        '"unit":"µs","issued":"2026-08-22T14:03:00Z","hops":1,"prev":"c1"}'
    )
    severed = "MESSAGE: card c1 was lost in prose"
    trace_a = _write_trace(
        tmp_path / "a.jsonl",
        [
            {"agent": "buyer-0", "kind": "send", "corr": "x1", "to": "seller-0", "msg": card, "ts": 0.0},
            {"agent": "seller-0", "kind": "receive", "corr": "x1", "from": "buyer-0", "msg": card, "ts": 0.0},
            {"agent": "seller-0", "kind": "send", "corr": "x2", "to": "buyer-1", "msg": same, "ts": 1.0},
            {"agent": "buyer-1", "kind": "receive", "corr": "x2", "from": "seller-0", "msg": same, "ts": 1.0},
        ],
    )
    trace_b = _write_trace(
        tmp_path / "b.jsonl",
        [
            {"agent": "buyer-0", "kind": "send", "corr": "y1", "to": "seller-0", "msg": card, "ts": 0.0},
            {"agent": "seller-0", "kind": "receive", "corr": "y1", "from": "buyer-0", "msg": card, "ts": 0.0},
            {"agent": "seller-0", "kind": "send", "corr": "y2", "to": "buyer-1", "msg": severed, "ts": 1.0},
            {"agent": "buyer-1", "kind": "receive", "corr": "y2", "from": "seller-0", "msg": severed, "ts": 1.0},
        ],
    )

    report = MODULE.analyze([trace_a, trace_b], rounds=5)
    hop1 = report["per_hop"][0]
    assert hop1["n_scored"] == 2
    assert hop1["n_unscored"] == 0
    assert hop1["T0"] == 1
    assert hop1["T2"] == 1
    assert hop1["T1_substring_diag"] == 1
    assert hop1["spread"]["T0_rate"]["mean"] == 0.5


def test_live_trace_matches_reported_measurement() -> None:
    report = MODULE.analyze([TRACE_DIR / "lost_in_handoff_fresh.jsonl"], rounds=5)

    assert report["excluded"] == {
        "originations": 3,
        "no_outbound": 0,
        "no_outbound_round_cap": 3,
    }
    assert [row["n_scored"] for row in report["per_hop"]] == [3, 3, 2, 2]
    assert [row["T0"] for row in report["per_hop"]] == [3, 3, 2, 2]
    assert all(row["T1"] == 0 for row in report["per_hop"])
    assert all(row["T2"] == 0 for row in report["per_hop"])
    assert sum(row["T0_core_byte_different"] for row in report["per_hop"]) == 0


def test_mock_trace_stays_unscored_negative_control() -> None:
    report = MODULE.analyze([TRACE_DIR / "lost_in_handoff_mock.jsonl"], rounds=5)

    assert report["excluded"] == {
        "originations": 3,
        "no_outbound": 0,
        "no_outbound_round_cap": 3,
    }
    assert all(row["n_scored"] == 0 for row in report["per_hop"])
    assert all(row["T0"] == 0 for row in report["per_hop"])
    assert all(row["T1"] == 0 for row in report["per_hop"])
    assert all(row["T2"] == 0 for row in report["per_hop"])
