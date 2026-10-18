# Hifza: policy schema and validation (`policy/`)

You own the **schema and validation** of the policy. Suyash owns keeping `policy/policy.example.toml` correct for the VM. Your main guide is [guard/docs/hifza.md](../../guard/docs/hifza.md).

## 1. Your part, in plain words

The policy is the guard's briefing: which files are confidential, which rooms a stamped person may still enter, and whether the guard only writes things down (audit) or actually stops people (enforce). Your job is to make sure a bad briefing is rejected loudly before the guard starts, instead of starting a guard with the wrong instructions.

## 2. Where it sits

```
 policy/policy.toml ──▶ guard/policy.py (validate, exit 2 on error) ──▶ guard.py ──▶ kernel maps
                              ▲
              --mode audit|enforce (CLI override)
```

## 3. Files you own

- The schema (keys, types, rules), as implemented in `guard/policy.py`
- `policy/docs/hifza.md`: this file (sections 6, 9, 10 only, during development)

Do not edit: `policy/policy.example.toml` content for VM paths (Suyash). Schema changes to it are a `contract:` commit.

## 4. What to build

Keys:

| Key | Type | Rule |
|---|---|---|
| `mode` | string | `"audit"` or `"enforce"`. CLI `--mode` overrides the file. |
| `protect` | list of strings | each path absolute and existing; `os.stat` (follows symlinks, so the real file is protected) |
| `allow` | list of strings | each parses with `ipaddress.ip_network(entry, strict=False)`; IPv4 and IPv6 |

Mode semantics: `audit` logs `WOULD_BLOCK` and blocks nothing. `enforce` blocks with `EPERM`. Default is `audit`.

On any error: clear message to stderr naming the key and value, exit **2**.

Cases `tests/test_policy.py` must cover:

- the example policy (with `protect` pointed at a temp file) parses
- `mode` missing or not in {audit, enforce} → exit 2
- relative `protect` path → exit 2
- non-existent `protect` path → exit 2
- symlinked `protect` path → resolves to the target's inode
- bad CIDR in `allow` → exit 2
- host bits set (`10.0.0.1/8`) is accepted (`strict=False`)
- IPv4 and IPv6 entries split correctly
- `--mode` override wins over the file

## 5. Contract excerpts

Contract excerpt (source of truth: ARCHITECTURE.md, section "Contract 2: Policy file"):

```toml
# SyscallGuard policy
# mode: "audit" logs WOULD_BLOCK without blocking. "enforce" blocks. Default to audit.
mode = "audit"

# Files whose readers get tagged. Absolute paths. Must exist at startup.
protect = [
  "/home/demo/syscallguard/demo/project/.env",
]

# Destinations a tagged process may still reach. CIDR. IPv4 and IPv6.
# Loopback must stay allowed: the internal API mock and the DNS stub (127.0.0.53) live there.
allow = [
  "127.0.0.0/8",
  "::1/128",
]
```

> Parsing (`guard/policy.py`): use `tomllib`. Validate that `mode` ∈ {audit, enforce}; that every `protect` path is absolute and exists (`os.stat`, which follows symlinks, so we protect the real file); and that every `allow` entry parses with `ipaddress.ip_network(strict=False)`. On any error, print a clear message to stderr and exit 2. A CLI `--mode` flag overrides the file.

## 6. Your milestones

- [ ] **M1 Tagging** (K + G, 18–19 Oct): Guard starts in audit mode and prints `READY`; `cat demo/project/.env` → `TAG` event for `cat`; `sudo bpftool map dump name tagged` shows the entry

Policy validation is a prerequisite for M1. Start now; no VM needed.

## 7. How to run and test your part

```bash
python3 -m unittest tests/test_policy.py      # any machine, no root
```

| If this happens | Check |
|---|---|
| Test passes on a missing file | You validated the path string, not `os.stat`. |
| `tomllib` ImportError | Python older than 3.11. |
| Symlinked file not protected | Inode taken with `os.lstat` instead of `os.stat`. |

## 8. Working with AI agents

- Default mode is `audit`; never change that default.
- Schema changes (new key, renamed key, new rule) are a `contract:` commit updating ARCHITECTURE.md and `docs/shared.md`; tell Suyash.
- `policy.py` must not import `bcc`.

Start-here prompt:

> I'm Hifza. Read AGENTS.md, docs/shared.md, policy/docs/hifza.md and ARCHITECTURE.md Contract 2. Implement validation in guard/policy.py exactly per section 4 and the test cases listed there. Stdlib only. At the end, update only sections 6, 9 and 10 of this file.

## 9. Open questions

- **Empty lists.** Is `protect = []` or `allow = []` valid? Not specified. (Empty `allow` in enforce mode would block all network for tagged processes, including DNS.)
- **Missing `mode` key.** Default to `audit`, or error? The example comment says "Default to audit".
- **Unknown keys.** Reject or ignore? Not specified.
- **Max sizes.** `protected_inodes` holds 256 entries and each allow trie 1024; whether validation enforces these limits is not specified.
- **Who writes `tests/test_policy.py`** (you vs Suyash). See guard/docs/hifza.md.

## 10. Work log

- 2026-10-18: file created.
