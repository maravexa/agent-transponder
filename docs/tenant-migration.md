# Local hardening compatibility and operator preflight

This is a runbook, not a migration program. No real data has been migrated.
Keep all services stopped while inventorying or changing a storage snapshot; do
not run either version against production until the inventory is approved.

## Identity decisions

The previous TLS identity transform was exactly
`strings.ReplaceAll(strings.ToLower(strings.TrimSpace(O[0])), " ", "-")`.
Only the first Organization value mattered; absent Organization used `_default`.
The new implementation validates and preserves `O[0]` exactly. It deliberately
has no fallback to a normalized directory, because a fallback could select a
different tenant's history. Direct EventStore callers previously only mapped an
empty ID to `_default`; they did not lowercase or replace spaces. They now must
supply a valid nonempty identity themselves.

| Certificate Organization | Previous directory | New behavior |
| --- | --- | --- |
| `acme`, `tenant-01`, `日本語` | unchanged | unchanged |
| `Acme`, `ACME` | `acme` | distinct literal names on case-sensitive storage |
| `Acme Corp` | `acme-corp` | `Acme Corp` |
| `acme-corp` | `acme-corp` | unchanged; previously collided with `Acme Corp` |
| `A  B` | `a--b` | `A  B` |
| `ÄCME` | `äcme` | `ÄCME` (Go Unicode lowercasing was applied previously) |
| leading/trailing Unicode whitespace | trimmed, then normalized | rejected |
| present empty/whitespace-only O | `_default` storage, empty event tenant | rejected |
| absent O | `_default` | `_default` |
| literal `_default` | `_default` | `_default`; still aliases absent O |
| `_DEFAULT` | `_default` | `_DEFAULT` |
| `.`, `..`, slash, backslash, colon, controls, invalid UTF-8 | previously unsafely accepted by identity layer | rejected |

For every newly accepted identity, the legacy mapping changes exactly when the
old transform differs from the literal input (Unicode uppercase or ASCII spaces
inside an otherwise valid ID). Internal non-ASCII spaces are not replaced by the
old transform. Rejected inputs may also have produced cleaned/escaped paths via
`filepath.Join`; do not interpret those as safe one-to-one renames. Filesystem
case folding, Unicode normalization, trailing-dot aliases, component length and
reserved names can introduce additional aliases or errors. Validate the actual
target filesystem. Prefer case-sensitive Linux storage; the validator is not a
portable filesystem-name uniqueness guarantee.

Exact identity can also change tenant policy matches, key buckets, API filters,
metrics labels, dashboards and authorization assumptions. Review all those uses,
not just directories. Old persisted JSON tenant IDs stay normalized; renaming a
directory does not update payload identity. Do not rewrite signed event payloads
or audit chains to make them match a new label. Root confinement is not tenant
authorization. Multiple agents/certificates assigned the same Organization are
still one tenant by design.

## Safe preflight and migration sequence

1. Schedule a maintenance window; stop ingestion, analyzer and exporter. Back up
   event, findings, cursor, audit and relevant configuration/certificates together,
   preserving ownership, group, modes and timestamps. Work on a separate snapshot.
   Record hashes and a rollback checkpoint. Never change live paths under running
   pinned roots or open cached event writers.
2. Inventory every active certificate's first O (including absent versus empty),
   its legacy transform, its new exact identity or rejection, and the directories
   and JSON tenant values actually present. Use Go's transform as above; Python
   lowercasing is not a substitute for all Unicode cases. Group by legacy mapping
   and by the target filesystem's equivalence rules. Include direct store callers,
   `_default`, root-level JSONL, nested paths, policy and keymanager references.
3. Inspect each configured root and every ancestor with `namei -l`; inventory the
   snapshot using `find ROOT -xdev -printf '%y %m %u %g %D:%i %n %p -> %l\n'`
   and mounts using `findmnt -R ROOT`. Repeat separately for all configured roots.
   Review symlinks, nonregular files, device/inode duplicates, link counts greater
   than one, mount boundaries, owner/group/ACLs and writable ancestors. These are
   read-only examples: substitute quoted, operator-verified paths. The checks
   are only meaningful while mutation is excluded; `-xdev` intentionally omits
   other mounts, which must be separately accounted for. Link counts reveal
   additional links but cannot locate every external hardlink.
4. Safest continuity choice: reissue certificates using the already-normalized,
   safe legacy tenant ID, with an explicit ownership map. That retains existing
   paths and JSON identity. Do not silently merge principals that previously
   collided. An already-mixed legacy directory cannot be separated from its
   normalized tenant field alone; independent certificate/agent records and
   historical ownership evidence are required. Quarantine unresolved collisions.
5. If exact new spelling is required, make an explicit old-to-new ownership plan.
   Prefer retaining immutable old history separately and starting new directories
   with a documented alias in downstream consumers. A rename is only safe after
   proving unique ownership and an absent destination, with services stopped;
   it still leaves old payload identities and changes cursor paths. Never bulk
   lowercase, merge directories, overwrite a destination, or use symlinks as
   migration aliases. Reject/reissue unsafe subjects before resuming ingestion.
6. Decide cursor handling below, validate on the snapshot with test credentials,
   and compare known event IDs, byte counts, findings, policy behavior, metrics
   labels and audit verification. Preserve shared reader-group access: new files
   request 0640 and directories 0750, subject to umask; existing files are not
   chmodded. Review actual ownership, ACLs and service umasks.
7. Only after operator approval apply the reviewed plan during the stopped window,
   then restart all services together. Roll back the complete checkpoint together
   if needed; do not roll back only the binary with new relative cursor keys.

## Legacy cursor replay

Previously `files[basename]` was shared by all tenants' same-date files. One offset
may have suppressed another tenant's events; its owner cannot be inferred from
that cursor. New keys are event-root-relative paths such as
`acme/2026-10-17.jsonl`. A root-level `2026-10-17.jsonl` retains its existing key.
Nested files without new keys start at zero; the old basename entry is retained,
not guessed or copied to all tenants. Successful polling persists separate keys.
Renaming any tenant directory again causes replay unless its verified relative
cursor keys are adjusted while stopped.

Default safe choice is replay, accepting duplicate findings/alerts and temporary
metrics inflation. Test downstream deduplication/suppression and capacity before
rollout. Replay is normally once after a successful cursor save, not an exactly-once
guarantee: cursor writes are atomic replacement but not fsynced, findings and
cursor writes are not one transaction, and failures/crashes can replay again.
Do not seed offsets to EOF merely to hide duplicates; that could skip events
already missed by the legacy basename collision. If replay is unacceptable,
reconstruct each file's consumed byte boundary from independently verified event
processing records, bounded by file size and a complete newline; preserve
`last_read`, use the new relative path and atomically replace the cursor on the
stopped snapshot. Without that evidence, retain replay or stop the rollout.

## Filesystem boundary limits

`os.Root` confines resolution to an opened storage directory; it allows relative
symlinks that resolve inside that root, including a tenant A link into tenant B.
Walks do not traverse directory symlinks, but direct opens can follow them and
leaf symlinks can be read. Hardlinks can alias an external file on the same
filesystem, and mounts/bind mounts can expose external content. Special files
can block I/O. None of these are prevented by tenant component validation.

Pinned roots survive rename/replacement of their configured path after opening;
therefore services can keep writing the old directory until restarted. Child
directory replacement may redirect accesses within the same root; cached writers
keep their old file descriptors. Root/ancestor replacement before opening remains
an operator trust issue. The exporter reopens roots for collection, whereas the
store/analyzer/audit pin them longer, so root replacement can split their view.
Audit resume, append and verification use separate opens, not a transactional
inode identity check. Keep storage and its parents non-writable by untrusted users;
shared readers must not have directory write permission. Strong isolation from a
hostile local storage writer requires a separate design (per-tenant roots and
permissions, mount constraints and no-follow/regular-file/inode policies), not a
claim that os.Root forbids symlinks. No such stronger guarantee is introduced here.

Regression fixtures: `internal/identity/compatibility_test.go`,
`internal/analyzer/confinement_test.go` and `internal/eventstore/confinement_test.go`.
