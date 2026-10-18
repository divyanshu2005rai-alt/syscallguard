# Suyash: policy example for the VM (`policy/`)

You keep `policy/policy.example.toml` correct for the VM and the demo. Hifza owns the schema and validation. Your main guide is [demo/docs/suyash.md](../../demo/docs/suyash.md).

## 1. Your part, in plain words

The policy is the guard's briefing: which files are confidential and which rooms a stamped person may still enter. You're the operator: you make sure the briefing names the real `.env` on the demo VM and lists exactly the rooms the demo needs, no more and no fewer.

## 2. Where it sits

```
 policy/policy.example.toml ──cp──▶ policy/policy.toml (VM paths) ──▶ guard.py -p ...
```

## 3. Files you own

- `policy/policy.example.toml`: content (paths, allowlist) kept correct for the VM
- `policy/docs/suyash.md`: this file (sections 6, 9, 10 only, during development)

Do not edit: the schema or validation rules (Hifza). Adding or renaming a key is a `contract:` commit.

## 4. What to build

**Choosing protected paths.** Absolute paths that exist at guard startup. The example uses `/home/demo/syscallguard/demo/project/.env`; change the home directory to match where the repo is checked out in the VM (`realpath demo/project/.env`). Real VM paths go in `policy/policy.toml`, which is gitignored and stays local; the committed example keeps the `/home/demo/...` placeholder. The guard protects the inode it finds at startup. If an editor replaces the file (save-as-new-file-and-rename), restart the guard.

**Why loopback must stay allowlisted.** The internal API mock (`127.0.0.1:8080`) and the systemd-resolved DNS stub (`127.0.0.53`) both live on loopback. Without `127.0.0.0/8` a tagged agent can't do its allowed work or even resolve a name. This is also why the attacker must run on the host, never on localhost.

**DNS and CDN pitfalls.** The allowlist is by address, not hostname. Allowlisting a CDN or cloud range allows everything else hosted there too, and exfil to an allowlisted destination is a known gap. DNS tunnelling through the allowed local resolver is also a known gap. Keep the allowlist minimal: loopback only for the demo.

**Audit-to-enforce workflow.**

1. Run in `audit` (`--mode audit` or `mode = "audit"`).
2. Run the demo agent; read the `WOULD_BLOCK` and `ALLOW` events.
3. Every `WOULD_BLOCK` should be the attacker and nothing else. If a legitimate destination shows up, add it to `allow`.
4. Only then switch to `--mode enforce`, inside the VM only.

## 5. Contract excerpts

Contract excerpt (source of truth: ARCHITECTURE.md, section "Contract 2: Policy file"):

```toml
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

## 6. Your milestones

- [ ] **M7 Freeze** (all, P leads, 21 Oct): VM snapshot saved; backup video recorded; runbook complete; 3 consecutive cold runs pass

The VM snapshot must include a `policy/policy.toml` with the VM's real path.

## 7. How to run and test your part

```bash
cp policy/policy.example.toml policy/policy.toml
sed -i "s#/home/demo/syscallguard/demo/project/.env#$(realpath demo/project/.env)#" policy/policy.toml
sudo python3 guard/guard.py -p policy/policy.toml --mode audit    # READY lists your path
```

| If this happens | Check |
|---|---|
| Guard exits 2 | Path doesn't exist or isn't absolute; read the stderr message. |
| No TAG on `cat .env` | Path points at a different file/inode than the one you read. |
| Agent's allowed POST is blocked | `127.0.0.0/8` missing from `allow`. |
| Agent can't resolve names | DNS stub 127.0.0.53 not covered by the allowlist. |

## 8. Working with AI agents

- Default `mode` stays `audit` in the example file. Enforce only via `--mode enforce`, only in the VM.
- Never widen the allowlist to make a demo "work"; find out why it was blocked.

Start-here prompt:

> I'm Suyash. Read AGENTS.md, docs/shared.md, policy/docs/suyash.md and ARCHITECTURE.md Contract 2. Check policy/policy.example.toml matches the demo topology; don't change the schema. At the end, update only sections 6, 9 and 10 of this file.

## 9. Open questions

None open. Resolved 18 Oct (see docs/shared.md): the example keeps the `/home/demo/...` placeholder; `policy/policy.toml` is gitignored.

## 10. Work log

- 2026-10-18: file created.
- 2026-10-18: docs updated with team decisions (TAG_INHERIT name not asserted, hook C emits no ALLOW, native IPv6 dropped, open questions resolved). See docs/shared.md.
