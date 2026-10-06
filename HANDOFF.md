# Mapping repository handoff

Updated: 2026-10-06. Working branch: `codex/mapping-boundaries`.
Base: `c340144b3b4071bd569b5fd15669300ee666dc88`.

## Current change

Repeated imports previously reused a snapshot id and set that snapshot as its own
parent. Reversions could overwrite earlier snapshots. Statement files also changed
in place, so historical impact comparisons could read later extraction results.

This branch makes identical imports idempotent and new revisions immutable. Format
2 snapshots bind exact statement objects and metadata by hash. Diff, drift, and
impact analysis read those bound statements. Existing format 1 stores remain
readable. Corrupt history and missing objects now raise errors. Document and object
identifiers cannot provide path traversal. See `docs/LINEAGE.md` for the API and
limits.

## Validation

The baseline has 128 passing tests. `tests/test_lineage_integrity.py` adds regression
coverage for retries, reversions, changed metadata and extraction, legacy reads,
cycles, missing objects, changed hashes, and unsafe paths. Run:

Validation on this branch: 148 tests pass. The risky-change lab returns the
expected exit 1. The policy-as-code lab blocks both change directions and exits 0.

```sh
python -m pip install -e '.[dev,ui,anydoc]'
python -m pytest -q
bash lab/simulate_risky_pr.sh   # expected exit 1: the critical change is blocked
bash lab/simulate_pac_lockstep.sh
```

A runtime that sets a SOCKS proxy also needs `httpx[socks]`. This is an environment
dependency. It does not change offline mapping behavior.

## Next boundaries

Use one writer per lineage store. Transactional recovery, concurrent commits,
external custody, and migration of already-corrupt legacy stores remain open.
Do not equate policy text, a candidate framework mapping, and evidence that a
control operates. A future Membrane integration must use an explicit tool adapter
with caller authorization and evidence. This branch does not connect the repos.
