# Document lineage

The lineage store retains document revisions and the exact statements used for
each revision. A later extraction or classification does not rewrite an earlier
snapshot. These records describe policy text and candidate mappings. They do not
establish that a control operates or that an assessment passed.

## Commit behavior

| Input | Result |
| --- | --- |
| Same document, source, version label, statements, and metadata as HEAD | Return HEAD with its original timestamp. Add no event. |
| Changed content, extraction, title, author, approval status, or metadata | Create a child snapshot. Retain the previous snapshot. |
| Revert to an earlier version after an intervening change | Create a new child. Do not reuse or overwrite the earlier snapshot. |
| Concurrent commits through this library on one local POSIX filesystem | Serialize under a store-wide writer lock. Select the parent while holding the lock. |
| Process interruption after a durable commit intent | The next HEAD read, commit, or `recover(doc_id)` completes that intent once. |
| Missing HEAD target, missing parent, cyclic legacy history, or hash mismatch | Raise `ValueError`. Do not return a partial history. |

## Stored format and API

Format 2 snapshots add `format_version: 2` and `statement_hashes`, keyed by the
original statement id. Statement files live at
`statements/by-hash/<sha256>.json`. Their digest covers canonical UTF-8 JSON with
sorted keys, compact separators, and no non-finite numbers. Markdown files remain
at `objects/<sha256>`. Reads verify these hashes.

The snapshot id is the first 20 hex characters of SHA-256 over its canonical
fields, excluding `snapshot_id` and `created_at`. The parent id is included, so a
reversion is a distinct revision. Format 2 reads verify this digest and the
statement reference keys. Timestamps are informational and are outside the digest.

Load statements for a particular snapshot with both its ids and its hashes:

```python
snapshot = store.head("pol-ac-001")
if snapshot is not None:
    statements = store.load_statements(
        snapshot.statement_ids,
        statement_hashes=snapshot.statement_hashes,
    )
```

Diff, drift, and impact analysis use these references. Missing statement objects
raise an error instead of silently reducing the comparison population.

`commit(...)` still returns a `DocumentSnapshot`. `commit_with_result(...)` returns
a `CommitResult` with `snapshot` and `created`. An identical retry sets `created`
to false. The analysis pipeline and watcher use this result and the snapshot's
actual parent. A concurrent writer cannot make them compare against an earlier
HEAD read. Repeated identical commits do not emit another impact alert.

## Concurrent writes and recovery

All updated writers and HEAD readers use `.writer.lock` with a bounded POSIX
advisory lock. The default timeout is five seconds; callers can set
`PolicyLineageStore(root, lock_timeout=...)`. A timeout raises `TimeoutError`
before the commit writes objects. The lock covers all documents because their
content objects share a directory. It is released when the process exits.

Objects and snapshots are published from complete, flushed temporary files.
The writer then atomically records `.pending-commit.json` in the document
directory. This intent names the new snapshot and its parent. Recovery validates
the snapshot, objects, and current HEAD; records the commit event once; publishes
HEAD; and removes the intent. A failure leaves the intent available for retry.
An unknown or conflicting intent raises an error and does not replace HEAD.

HEAD reads automatically finish a valid pending commit. They therefore require
write access and may wait for the writer lock. To recover explicitly:

```python
snapshot = store.recover("pol-ac-001")
```

Readers never observe a partially written object through this library. A failure
before the intent can leave orphan objects. A later identical commit can reuse a
complete orphan snapshot. The event log is atomically rewritten when an event is
added. This favors recovery simplicity over throughput for very long histories.

Snapshots without `format_version` use format 1. They read their existing legacy
statement files. New commits do not change those files or rewrite old snapshots.
There is no automatic migration or repair of prior corruption. The first new
commit after a legacy HEAD may create a format 2 child even when its text matches.
Calling `load_statements(ids)` without hashes selects the legacy lookup only.

## Storage boundary and limits

- A document id is a single nonempty path component of at most 128 characters.
  Path separators, `.` and `..`, and control characters are rejected before writes.
- Snapshot and object reads accept only the expected hexadecimal identifiers.
  Managed store directories and document paths must not be symlinks. The root is
  an operator-selected, trusted local directory, not a sandbox for hostile writers.
- Concurrent workers must use this updated library and the same local POSIX
  filesystem. Stop older writers before upgrading. Network filesystems,
  cross-host locks, hostile local writers, and distributed transactions are not
  supported. File and directory flushes are used, but arbitrary power-loss and
  storage-device failure have not been validated.
- Recovery covers lineage publication. External alert delivery is outside the
  commit transaction. A crash can leave a committed change without its alert.
  Reliable delivery still needs an outbox and destination deduplication. Failed
  pre-intent writes can leave temporary or unreferenced objects; automatic garbage
  collection is not implemented.
- Hashes detect mismatches against retained references. They do not authenticate
  an author, approver, or publisher. A writer that can rewrite all references can
  replace history. External custody is a separate requirement.
- Format 1 history has no exact statement hashes. This change cannot reconstruct
  legacy statement revisions that were already overwritten.
