# Lost In Handoff Verification Record

Status: scorer and fixture verification complete; apparatus reproduction remains
unverified and the rendered-prompt gate is FAIL.

## Rebase

- Pre-rebase commit: `6b8c5c6d820a8eb2ef562b9a08c95e8c39f27692`
- Upstream base: `717616365abfc7ef0fe87b0195aaa1e840e4a74a`
- rebased_base: `3435f272a81cd16fd46555df43e5093c4a02b44f`
- Publication tip: the commit on the public ref `lost-in-handoff-clean-rebased`
  that adds this record's ref-restoration note. Its SHA is not embedded here — a
  commit cannot contain its own hash — and should be read from the remote ref.
  `3435f272a81cd16fd46555df43e5093c4a02b44f` remains the rebased base and must not
  be represented as the publication tip.
- Conflict: Git relocated the added scenario from `scenarios/` to
  `tests/fixtures/upstream/` after upstream removed the scenario corpus. This
  record previously stated that the scenario contents were not changed. That
  statement was incorrect. The rebased fixture initially diverged from
  `78dbde5` on `agents.llm_model` (`claude-sonnet-4-20250514` rather than
  `claude-sonnet-4-6`). The model field has been restored to the historical
  value. The fixture remains an adapted packaging fixture, derived from the
  `78dbde5` scenario and not byte-identical to it: the additive branch uses
  `template: lost-in-handoff` rather than historical `template: auto`, and the
  fixture carries packaging-oriented comments/output metadata. The discrepancy
  and correction are recorded here rather than silently resolved.
- Historical `78dbde5` scenario SHA-256:
  `d219885370bb9e41dde2b868d3930909b361f7671810881b0bf8f5267d654998`
- Corrected adapted packaging fixture SHA-256:
  `e2e9e12e1efa4d71c999dc52a88b885d34698afc2cb3e8b6c77d4f969143f6d8`
- Local `lost-in-handoff-clean` was rebased in place on 2026-08-30 from the
  packaged commit `6b8c5c6d820a8eb2ef562b9a08c95e8c39f27692` onto current upstream,
  producing `3435f272a81cd16fd46555df43e5093c4a02b44f`. The historical
  `lost-in-handoff` ref remains at
  `78dbde5c5163e2bbbb34d18c1731d9de6438c3e0`.
- Additive files: `scripts/hop_decay.py`, `templates/agents/lost-in-handoff.yaml`,
  `tests/fixtures/upstream/lost_in_handoff.yaml`, `tests/test_hop_decay.py`,
  `traces/lost_in_handoff_fresh.jsonl`, and `traces/lost_in_handoff_mock.jsonl`.
- `git diff 7176163 -- templates/agents/marketplace-buyer.yaml templates/agents/marketplace-seller.yaml packages/nest-shell/nest_shell/llm.py` was empty.

**Ref restoration.** `lost-in-handoff` was absent from the remote when this record
was written; the local branch was intact at
`78dbde5c5163e2bbbb34d18c1731d9de6438c3e0` and the commit object remained
reachable server-side by SHA. The ref was recreated server-side from that
surviving commit object on 2026-08-30, at the same commit, with contents
unchanged. No history was rewritten. This record previously implied the ref had
been continuously published; that was incorrect.

**Publication coverage.** This verification record covers the commit that adds this record
and the packet state contained in that commit. If later commits exist on this branch, they
postdate this verification and are not covered by it.

## Scorer And Fixtures

The tests import the committed scorer with:

```python
SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "hop_decay.py"
)
```

With `ANTHROPIC_API_KEY` removed from the command environment, all nine tests
passed: seven scorer unit tests and two trace-backed regression tests.

Both trace-backed regressions assert the same exclusion dictionary
`{originations: 3, no_outbound: 0, no_outbound_round_cap: 3}`. They therefore
show consistency with the rebased scorer's accounting but do not discriminate
the live trace from the mock trace and are not independent validation of the
exclusion partition on which the historical and rebased instruments disagree.

- Historical trace SHA-256:
  `01ae97f986716233e0e8c30da8684db5618bb224343532c6f252d5b614adfee1`
- Mock trace SHA-256:
  `728bc285c5c74ee6f3b85297038729d6eca7e7f08395ea34130277df58ae9bd2`
- Historical scorer: commit `78dbde5c5163e2bbbb34d18c1731d9de6438c3e0`,
  SHA-256 `4fac72c8174ffb0047ca713f0a9de6084fcee441aef1d374fe485ea49ead8a83`.
  It reports 13 receives, 10 scored hops, 1 unrelayed inbound, and 2
  round-cap artifacts.
- Rebased scorer SHA-256:
  `08f89b9338bbed4a596e4babb20085534bb27910c6fc423af805b9df6c6e67ba`.
  It reports 13 sends, 13 receives, 10 scored T0 relays, depths `3/3/2/2`,
  zero T1, zero T2, zero byte-different T0, 0 no-outbound, and 3 round-cap
  artifacts.
- The mock trace reports 23 sends and 23 receives; all candidate relays are
  unscored because their inbound payloads are not JSON cards.

On the same trace bytes, the historical and rebased instruments both score ten T0 relays at depths 3/3/2/2, but they identify different relay pairs. The aggregate agreement does not reflect a common reconstruction. They also disagree on exclusion accounting.

Accordingly, neither instrument is treated here as an independently validated reconstruction oracle; each result is reported with its scorer identity and digest.

These observations show that two plausible reconstruction procedures do not converge on the same hop graph from this trace. They do not establish that no unique reconstruction exists or that either instrument is incorrect.

Pair identity was compared by instrumenting scratch copies of both scorers, outside either worktree, to emit `(receive_file_index, send_file_index, depth)` per scored hop, then comparing as sets and as sorted records.

## Instrument Identity

```yaml
historical_instrument:
  commit: 78dbde5
  scripts/hop_decay.py_sha256: 4fac72c8174ffb0047ca713f0a9de6084fcee441aef1d374fe485ea49ead8a83
  result: 10 T0 relays, depths 3/3/2/2
  pairing_hop_reconstruction: receive-only, latest-preceding
  exclusion_classification: receive ordinal against rounds; 1 unrelayed + 2 round-cap
rebased_instrument:
  rebased_base: 3435f272
  scripts/hop_decay.py_sha256: 08f89b9338bbed4a596e4babb20085534bb27910c6fc423af805b9df6c6e67ba
  result: 10 T0 relays, depths 3/3/2/2
  pairing_hop_reconstruction: per-send correlation ID, all-event ordering
  exclusion_classification: receive ordinal against rounds; 0 unrelayed + 3 round-cap
trace:
  traces/lost_in_handoff_fresh.jsonl_sha256: 01ae97f986716233e0e8c30da8684db5618bb224343532c6f252d5b614adfee1
```

## Duplicate-File Disposition

Four untracked duplicate-named files overlapping the scorer, tests, and trace
fixtures were removed before all eight duplicate/canonical hashes were recorded.
Their byte identity with the canonical files therefore cannot now be established.
No attempt was made to reconstruct that evidence after the fact. This is
recorded as a provenance limitation, not as a verification failure.

## Prompt-Gate Evidence

- Oracle buyer and seller prompts were distinct role-specific system strings.
- Role-neutral additive rendered system SHA-256:
  `90d6bdcbdaca89af33cc315cbe13a01af106bb8c0d5f07600604cde251893d03`
- Role-neutral additive rendered system length: `1441` bytes for both buyer and seller.
- Role-neutral additive rendered buyer = role-neutral additive rendered seller = raw
  `lost-in-handoff.yaml` `system_prompt` scalar.
- Verdict: FAIL. The rebased role-neutral template does not reproduce the
  historical role-specific prompt apparatus.

> These results verify the shipped scorer's interpretation of fixed trace fixtures only.
> They do not verify that the rebased branch's prompt apparatus generated those fixtures.
