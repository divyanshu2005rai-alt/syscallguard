# Shared changes log

## Purpose

If you change something another track depends on, record it here. If you are about to start work, read the entries added since you last worked.

This is how news travels between tracks. Nobody edits another person's file; they read this log, and their agent picks up the change next session.

## When to write an entry (required)

- Any `contract:` change: structs in `guard/bpf/sg_common.h`, map names, the JSON event schema, the WebSocket protocol, the policy format.
- Any change to a function signature another track calls (e.g. `decode_event` in `guard/events.py`).
- Renaming or moving a file another track references.
- Changing a CLI flag, port, or file path used in another track's runbook or commands.
- Discovering that a documented behaviour is wrong (in `ARCHITECTURE.md`, `AGENTS.md`, `README.md` or someone's person file).
- Creating a new person file because you started work in a new folder.

A `contract:` commit must include its entry here **in the same commit**.

## When not to write

Work that stays inside your own files and changes nothing another track can see. That goes in the work log of your own person file instead.

## Format

- Newest entries at the bottom. Append-only.
- Never edit or delete someone else's entry. To correct one, add a new `correction` entry that points at it.
- Heading line: `### <date> · <person> (track <X>) · <kind>`, where `<kind>` is exactly one of `contract`, `signature`, `path`, `correction`.
- Then exactly these four fields: **What changed**, **Who is affected**, **Action required**, **Commit**.

Template:

```
### YYYY-MM-DD · Name (track X) · contract|signature|path|correction
**What changed:** one or two sentences.
**Who is affected:** names, and which of their files.
**Action required:** name — what they must do. Or "none, informational".
**Commit:** the commit subject line.
```

---

## Entries

### 2026-10-18 · Setup (track all) · contract
**What changed:** Initial contracts are in place: Contract 1 (`guard/bpf/sg_common.h` structs and the six map names), Contract 2 (policy TOML), Contract 3 (guard CLI and JSON event schema), Contract 4 (bridge WebSocket protocol). All are written down in `ARCHITECTURE.md`. The `decode_event(data, ctx)` signature in `guard/events.py` is agreed and documented in `guard/docs/divyanshu.md`.
**Who is affected:** Everyone. Azaan (structs/maps), Hifza (loader, policy), Divyanshu (decoder, bridge), Devansh (dashboard consumes Contracts 3 and 4), Suyash (demo and tests rely on all four).
**Action required:** none, informational. Build against these; propose changes with a `contract:` commit plus an entry here.
**Commit:** chore: bootstrap SyscallGuard repository
