# Azaan: Track K, kernel enforcement (`guard/bpf/`)

## 1. Your part, in plain words

Think of the server as an office building and every running program as a person inside it. Some people need to read confidential files to do their job. SyscallGuard is a guard at the exit doors.

You build the guard and the stamps. When any program opens a protected file (the `.env`), your code stamps its hand (adds its process ID to the `tagged` map). Anyone that stamped program spawns gets a stamp too. When a stamped program tries to leave the building (connect or send to a network address), your code checks the address against the list of approved rooms (the allowlist). Approved: let it through. Not approved: refuse with `EPERM` before a single byte leaves. Every decision is written to a ring buffer so the rest of the system can show it.

Your code runs inside the Linux kernel as eBPF programs, so the untrusted program can't skip it. A program can ignore a rule written inside itself; it can't skip the kernel.

## 2. Where it sits

```
 guard.py (Hifza) ──fills──▶ protected_inodes, allow_v4, allow_v6, config
                                       │
   any process ── open() ──▶ Hook A ───┤──▶ tagged (map)
   any process ── fork   ──▶ Hook D ───┤
   any process ── exit   ──▶ Hook E ───┤
   any process ── connect ─▶ Hook B ───┤── check_dest ──▶ allow / EPERM
   any process ── send    ─▶ Hook C ───┘
                                       │ struct sg_event
                                       ▼
                               events (ring buffer)
                                       │
                                       ▼
            guard.py polls ──▶ events.py decode (Divyanshu) ──▶ JSON ──▶ bridge ──▶ dashboard
```

## 3. Files you own

- `guard/bpf/sg_common.h`: Contract 1 structs and constants (shared; change only via `contract:` commit)
- `guard/bpf/syscallguard.bpf.c`: all hooks and map declarations
- `guard/docs/azaan.md`: this file (sections 6, 9, 10 only, during development)

Do not edit: `guard/guard.py`, `guard/policy.py` (Hifza), `guard/events.py`, `bridge/` (Divyanshu), `dashboard/` (Devansh), `demo/`, `scripts/`, `tests/` (Suyash), `ARCHITECTURE.md` except in a `contract:` commit.

## 4. What to build

All in `guard/bpf/syscallguard.bpf.c`, compiled by bcc at load time. `#include "sg_common.h"` (guard.py passes `-I<abs path to guard/bpf>`).

**Maps.** Declare all six exactly as in the Contract 1 table below. Names matter: guard.py looks them up by name.

**Hooks.** Five, one per row of the hook table below:

- **A `file_open`**: read `file->f_inode->i_ino`; if in `protected_inodes`, upsert `tagged[tgid] = {now, ino, 0}`, emit `TAG`. Always return 0. Never deny an open.
- **B `socket_connect`**: pull family, address and port out of `address`, call `check_dest(..., SG_HOOK_CONNECT)`, return its result. Hook B is the only hook that emits `ALLOW`.
- **C `socket_sendmsg`**: if `msg->msg_name` is non-NULL, use that sockaddr (UDP `sendto`, TCP Fast Open). Otherwise use the connected peer from `sock->sk->__sk_common` (`skc_family`, `skc_daddr` / `skc_v6_daddr`, `skc_dport`). Unconnected with no address: return 0. Then `check_dest(..., SG_HOOK_SENDMSG)`. Hook C never emits `ALLOW`: an allowed send is silent, so chatty connections don't flood the ring buffer.
- **D `sched_process_fork`**: if parent tgid ≠ child tgid (new process, not a thread) and parent is tagged, insert `tagged[child_tgid] = {now, parent.ino, parent_tgid}`, emit `TAG_INHERIT` with `tgid` = child and `parent_tgid` = parent. The hook runs at fork, before the child calls `exec`, so `comm` is the parent's name. That's accepted: TAG_INHERIT does not assert a process name.
- **E `sched_process_exit`**: if `pid == tgid` (thread-group leader) and tagged, delete and emit `UNTAG`.

**`check_dest`**: a static helper implementing the decision logic below. Order matters: config lookup, then the `tagged` lookup (fast path out for untagged), then v4-mapped-v6 normalisation, family filter, LPM lookup, mode.

**Event fields you fill** (`struct sg_event`): `ts_ns` = `bpf_ktime_get_ns()`, `ino` from the tag, `type`, `hook`, `tgid`, `parent_tgid` (TAG_INHERIT only), `family`, `dport` (host byte order; `skc_dport` and `sin_port` are network order, convert), `daddr` (IPv4 in first 4 bytes, network order), `comm` via `bpf_get_current_comm()`.

**Rules you must follow:**

- Key `tagged` by **TGID** (`bpf_get_current_pid_tgid() >> 32`), never by thread id.
- Use `bpf_probe_read_kernel()` for pointer chasing whenever bcc's automatic rewriting is unclear (`sockaddr`, `msghdr`, `sk_common`).
- Emit with `events.ringbuf_reserve()` + `events.ringbuf_submit()`; this keeps the 64-byte+ event off the 512-byte stack. If reserve returns NULL, skip the event but still return the verdict.
- Hooks B and C fire on every connect/send on the whole machine. The untagged path must be **one** map lookup and return.
- No pass-through of earlier LSM verdicts. If SELinux denies first, your program never runs.
- Match on inode number only (`i_ino`). Collisions across filesystems are an accepted risk (ARCHITECTURE.md, Design decisions); don't add device matching unasked.
- LSM, tracepoint and raw-tracepoint probes auto-attach when bcc loads them. You don't attach anything by hand.

### Known gaps (documented, don't fix silently)

- **Editor replaces the protected file.** The guard reads `st_ino` once at startup. An editor that saves by writing a new file and renaming it over `.env` gives it a new inode, so the guard silently stops protecting it until restarted. Not handled. Demo rule (in the runbook): never edit `.env` while the guard is running; restart the guard if you do.
- The other known gaps are listed in ARCHITECTURE.md, "Known gaps".

## 5. Contract excerpts

Contract excerpt (source of truth: ARCHITECTURE.md, section "Contract 1: Kernel structs and maps"):

```c
struct sg_tag_info {
    u64 ts_ns;          /* when tagged (bpf_ktime_get_ns) */
    u64 ino;            /* inode of the protected file that caused the tag */
    u32 parent_tgid;    /* 0 if tagged directly, else the tgid it inherited from */
    u32 _pad;
};

struct sg_event {
    u64 ts_ns;
    u64 ino;            /* protected file inode (from tag info), 0 if n/a */
    u32 type;           /* SG_EV_* */
    u32 hook;           /* SG_HOOK_* */
    u32 tgid;
    u32 parent_tgid;    /* TAG_INHERIT only */
    u16 family;         /* AF_INET=2, AF_INET6=10, 0 if n/a */
    u16 dport;          /* host byte order */
    u8  daddr[16];      /* IPv4 in first 4 bytes, network order */
    char comm[16];
};
```

(The `SG_EV_*`, `SG_HOOK_*`, `SG_MODE_*` constants and `sg_config` / `sg_lpm_v4` / `sg_lpm_v6` are in `guard/bpf/sg_common.h`.)

| Name | bcc declaration | Written by |
|---|---|---|
| `protected_inodes` | `BPF_HASH(protected_inodes, u64, u32, 256)` | guard.py at startup (value = index into policy `protect` list) |
| `tagged` | `BPF_HASH(tagged, u32, struct sg_tag_info, 16384)` | hooks A, D (insert), E (delete) |
| `allow_v4` | `BPF_LPM_TRIE(allow_v4, struct sg_lpm_v4, u8, 1024)` | guard.py |
| `allow_v6` | `BPF_LPM_TRIE(allow_v6, struct sg_lpm_v6, u8, 1024)` | guard.py |
| `config` | `BPF_ARRAY(config, struct sg_config, 1)` | guard.py |
| `events` | `BPF_RINGBUF_OUTPUT(events, 64)` (64 pages) | all hooks |

Contract excerpt (source of truth: ARCHITECTURE.md, section "Hooks"):

| ID | Attach point (bcc macro) | Logic |
|---|---|---|
| A | `LSM_PROBE(file_open, struct file *file)` | `ino = file->f_inode->i_ino`. If `ino` in `protected_inodes`, then upsert `tagged[tgid] = {now, ino, 0}` and emit `TAG`. Always `return 0` (never deny opens). |
| B | `LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)` | Run `check_dest(family, addr, port, SG_HOOK_CONNECT)` on the address being connected to. Hook B is the only hook that emits `ALLOW`. |
| C | `LSM_PROBE(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)` | If `msg->msg_name` is non-NULL, the destination is that sockaddr (UDP `sendto`, TCP Fast Open). Otherwise use the connected peer from `sock->sk->__sk_common` (`skc_family`, `skc_daddr` / `skc_v6_daddr`, `skc_dport`). Unconnected with no address → return 0. Then `check_dest(...)`. Never emits `ALLOW`: an allowed send is silent; a disallowed one emits `WOULD_BLOCK` or `BLOCK`. |
| D | `RAW_TRACEPOINT_PROBE(sched_process_fork)` | `parent = ctx->args[0]`, `child = ctx->args[1]` (`struct task_struct *`). Read `parent->tgid` and `child->tgid`. If they differ (a new process, not a thread) and the parent tgid is in `tagged`, insert `tagged[child_tgid] = {now, parent.ino, parent_tgid}` and emit `TAG_INHERIT`. |
| E | `TRACEPOINT_PROBE(sched, sched_process_exit)` | `pid_tgid = bpf_get_current_pid_tgid()`. If `pid == tgid` (thread-group leader) and the tgid is in `tagged`, delete it and emit `UNTAG`. |

Contract excerpt (source of truth: ARCHITECTURE.md, section "Decision logic"):

```
check_dest(family, addr, port, hook):
    cfg = config[0];  if cfg missing → return 0
    tgid = bpf_get_current_pid_tgid() >> 32
    tag  = tagged.lookup(tgid);  if !tag → return 0           # fast path: untagged
    if family == AF_INET6 and addr is ::ffff:a.b.c.d → family = AF_INET, addr = a.b.c.d
    if family not in {AF_INET, AF_INET6} → return 0           # AF_UNIX etc. are a known gap
    if allow_v4/allow_v6 LPM lookup (prefixlen 32/128) hits → emit ALLOW only if hook == SG_HOOK_CONNECT; return 0
    if cfg.mode == AUDIT → emit WOULD_BLOCK; return 0
    emit BLOCK; return -EPERM
```

## 6. Your milestones

- [x] **M1 Tagging** (K + G, 18–19 Oct): Guard starts in audit mode and prints `READY`; `cat demo/project/.env` → `TAG` event for `cat`; `sudo bpftool map dump name tagged` shows the entry
- [ ] **M2 Inheritance & cleanup** (K, 19 Oct): `python3 -c "open('demo/project/.env').read(); import subprocess; subprocess.run(['sleep','1'])"` → `TAG` (python3) + `TAG_INHERIT` for the child tgid with `parent_tgid` = the python3 tgid (process name not asserted); after exit both get `UNTAG` and the map is empty of them
- [ ] **M3 Connect enforcement** (K + G, 19 Oct): Enforce mode: tagged `agent.py --exfil direct` → `PermissionError` + `BLOCK`; its POST to 127.0.0.1:8080 succeeds with `ALLOW`; an untagged `python3 -c` connect to the attacker succeeds; audit mode → all succeed + `WOULD_BLOCK`
- [ ] **M4 Sendmsg** (K, 20 Oct): `--exfil udp` and `--exfil preconnect` blocked with `BLOCK hook=sendmsg`
- [ ] **S1 Stretch** (K, after M7): `socket_create` denies `AF_PACKET`/`SOCK_RAW` for tagged processes
- [ ] **S2 Stretch** (finale, 26–30 Oct; K, after the department round): `file_permission` hook: a tagged process writing to a pipe/file taints that inode; reading a tainted inode tags the reader. `cat .env | curl ...` becomes blocked

S2 is yours alone (K), not shared with G. For M7 you also verify Suyash's backup video.

**Start now:** M0 in the VM; then Hook A plus the maps. Use `scripts/lsm_smoke_test.py` as a template for a throwaway loader until Hifza's `guard.py` lands.
**Blocked by:** Hifza's loader for real acceptance runs (M1, M3). Suyash's `agent.py` for M3/M4 acceptance.
**You block:** Hifza and Divyanshu (they need the map names and struct layout fixed, so agree Contract 1 first), and Suyash's attack matrix (M6).

You pair tightly with Hifza: her loader is how your hooks get tested. Agree Contract 1 with her (and Divyanshu, who decodes `sg_event`) before writing hooks.

## 7. How to run and test your part

Everything here runs **inside the VM**. You can't test kernel hooks without it.

```bash
scripts/check_env.sh                       # all PASS
sudo python3 scripts/lsm_smoke_test.py     # prints 5 "sg smoke: file_open" lines, exits 0

# Once guard.py exists (audit mode only until M3):
cp policy/policy.example.toml policy/policy.toml   # fix the protect path for your VM
sudo python3 guard/guard.py -p policy/policy.toml --mode audit --debug
# in another shell:
cat demo/project/.env                      # expect a TAG line with "comm":"cat"
sudo bpftool map dump name tagged          # expect cat's tgid while it lives
sudo bpftool prog list | grep -i lsm       # your programs are loaded
sudo cat /sys/kernel/debug/tracing/trace_pipe   # bpf_trace_printk output
```

Ctrl-C on `guard.py` detaches every hook instantly. That's your safety valve.

| If this happens | Check |
|---|---|
| bcc fails with confusing header/compile errors | `kernel-devel` must match `uname -r` exactly (`rpm -q kernel-devel-$(uname -r)`). Fix the package first. |
| Load fails with a long verifier log | The cause is usually in the last ~20 lines. Look for the instruction it rejected. |
| "invalid mem access 'map_value_or_null'" | You used a map lookup result without a NULL check. |
| "R? invalid mem access" / pointer deref rejected | Read the kernel pointer with `bpf_probe_read_kernel()` into a local. |
| "combined stack size ... too large" | Event struct on the stack. Use `ringbuf_reserve()` instead. |
| "back-edge" / unbounded loop | Only bounded loops; unroll the 16-byte address compare. |
| No TAG for `cat .env` | Is the inode in `protected_inodes` (`bpftool map dump name protected_inodes`)? Did the file get replaced (editors save to a new inode)? Restart the guard. |
| Tag disappears while process is still running | Known gap: the thread-group leader exited while worker threads run. Expected. |
| Machine loses network | You're in enforce mode with a bad allowlist. Ctrl-C the guard. Use audit mode while developing. |

## 8. Working with AI agents

Safety rules that apply here (from AGENTS.md):

- Default `mode` is `audit`. Use `enforce` only inside the VM. Never run `guard.py` in enforce mode on a developer's host machine.
- `sudo` is only for `guard.py`, `lsm_smoke_test.py` and `attack_matrix.py`.
- Contracts are law: changing `sg_common.h` or a map name means a `contract:` commit that updates `ARCHITECTURE.md`, `sg_common.h` and `docs/shared.md` together.

Conventions: bcc restricted C, kernel style (tabs or 4 spaces, match the file), one static helper `check_dest`, no `#include` beyond `sg_common.h` and what bcc provides. Comment the "why" for every verifier workaround.

Common pitfalls: keying by thread id instead of TGID; forgetting `dport` byte order; reading `msg->msg_name` without `bpf_probe_read_kernel`; doing work before the `tagged` lookup in `check_dest` (slows every connect on the machine); denying in Hook A.

Commit format: `feat(kernel): M1 hook A tagging`, `fix(kernel): null-check config lookup`, `contract: ...`.

Start-here prompt to paste to an agent:

> I'm Azaan, Track K. Read AGENTS.md, docs/shared.md, guard/docs/azaan.md and ARCHITECTURE.md. Work only in guard/bpf/. Implement the next unticked milestone in section 6 of my file, following the hook table and check_dest logic exactly. Do not change sg_common.h or map names without asking me. Don't run anything with sudo; give me the commands to run in the VM. At the end, update only sections 6, 9 and 10 of my file.

## 9. Open questions

- **Loader cflags need `-fms-extensions`.** Kernel 7.x headers embed anonymous tagged structs (`struct __filename_head;` inside `struct filename` in `linux/fs.h`), a Microsoft C extension the kernel builds with. Without the flag bcc's clang drops the member, so `static_assert(sizeof(struct filename) % 64 == 0)` fails, and any struct using the extension would get wrong offsets. Verified on the host: compile fails without the flag and succeeds with it (7.2.9 headers). ARCHITECTURE.md and the brief still say `cflags=["-I<abs path to guard/bpf>"]` only. Needs a `contract:` commit once the VM run confirms. Hifza notified via docs/shared.md.
- **bpftool name for `protected_inodes`.** Kernel map names are capped at 15 characters, so the map is probably visible as `protected_inode`, and `bpftool map dump name protected_inodes` (section 7, and Hifza's troubleshooting table) would fail. Confirm in the VM.

## 10. Work log

- 2026-10-18: file created. Bootstrap only; no kernel code yet.
- 2026-10-18: docs updated with team decisions (TAG_INHERIT name not asserted, hook C emits no ALLOW, native IPv6 dropped, open questions resolved). See docs/shared.md.
- 2026-10-18: editor/inode issue documented as a known gap; runbook rule added (see docs/shared.md).
- 2026-10-19: M0 passed in the VM (check_env all PASS, lsm_smoke_test OK, kernel 7.2.10-200.fc44). Box is Suyash's, not ticked here.
- 2026-10-19: hook A (file_open tagging) and all six Contract 1 maps written; compiles against 7.2.9 headers with -fms-extensions; throwaway loader in scratch/azaan/. M1 acceptance pending in the VM.
- 2026-10-19: M1 passed in the VM with scratch/azaan/load_hook_a.py: `cat demo/project/.env` → TAG with comm=cat, ino=1532 (matches `stat` and the `protected_inode` map); `tagged` held exactly one entry, for cat's tgid. guard.py `READY` is Track G's half and not a Track K dependency.
- 2026-10-19: M2 hooks D (sched_process_fork: inherit to new processes only, comm not asserted) and E (sched_process_exit: delete only when pid == tgid) written; event emission moved into a shared `emit()` helper used by A, D and E. Host compile (7.2.9 headers, bcc 0.35.0, non-root) passes clang; verifier and M2 acceptance pending in the VM.
- 2026-10-20: M3 hook B (socket_connect) and check_dest written per the Decision logic: config then tagged lookup, v4-mapped v6 -> v4, LPM allow check, ALLOW only from hook B, audit -> WOULD_BLOCK, else BLOCK + -EPERM. Non-INET families return before any map lookup. emit() now carries family/daddr/dport. Scratch loader gained --mode/--allow and always fills config (an empty config has mode 0, which check_dest treats as enforce), filling protect last. Host compile passes clang; verifier and M3 acceptance pending in the VM.
