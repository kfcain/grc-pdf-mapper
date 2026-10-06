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

The continuation adds a store-wide POSIX writer lock and recoverable commit
intents. Concurrent processes keep one complete revision chain. HEAD reads finish
valid pending commits after a process interruption. Objects publish atomically;
recovery writes each commit event once. The pipeline and watcher compare against
the actual committed parent and skip alerts for an identical retry.

## Validation

The original baseline has 128 passing tests. `tests/test_lineage_integrity.py`
covers retries, reversions, metadata and extraction changes, legacy reads, corrupt
history, hashes, and paths. `tests/test_lineage_concurrency.py` adds 12 cases for
concurrent processes, commit interruption, process death, lock timeout, recovery
conflicts, complete orphans, and exact-parent pipeline and watcher alerts.

Validation on this branch: 160 tests pass. The risky-change lab returns the
expected exit 1. The policy-as-code lab blocks both change directions and exits 0.
Run:

```sh
python -m pip install -e '.[dev,ui,anydoc]'
python -m pytest -q
bash lab/simulate_risky_pr.sh   # expected exit 1: the critical change is blocked
bash lab/simulate_pac_lockstep.sh
```

A runtime that sets a SOCKS proxy also needs `httpx[socks]`. This is an environment
dependency. It does not change offline mapping behavior.

## Next boundaries

All writers must use this updated library on one local POSIX filesystem. Cross-host
coordination, alert delivery through a durable outbox, external custody, and
migration of already-corrupt legacy stores remain open. Concurrent local commits
and recovery after a writer process dies now have regression coverage.
Do not equate policy text, a candidate framework mapping, and evidence that a
control operates. A future Membrane integration must use an explicit tool adapter
with caller authorization and evidence. This branch does not connect the repos.
