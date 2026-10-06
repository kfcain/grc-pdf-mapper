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
- Use one writer per store. Concurrent writers and atomic transactions across
  snapshot files, HEAD, and the event log are not supported. HEAD replacement is
  atomic, but a process crash can leave an orphan object or incomplete event log.
- Hashes detect mismatches against retained references. They do not authenticate
  an author, approver, or publisher. A writer that can rewrite all references can
  replace history. External custody is a separate requirement.
- Format 1 history has no exact statement hashes. This change cannot reconstruct
  legacy statement revisions that were already overwritten.
