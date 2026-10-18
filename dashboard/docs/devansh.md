# Devansh: Track U, dashboard (`dashboard/`)

## 1. Your part, in plain words

Think of the server as an office building and every running program as a person inside it. SyscallGuard is a guard at the exit doors: anyone who touched a confidential file gets a stamp on their hand, and a stamped person may only go to approved rooms. If a stamped person heads for the street, the guard stops them.

You build the **security screen**. It shows, live: whether the building is protected, who is stamped right now, every incident as it happens, and the guard's current instructions. When the guard stops someone, the screen turns red with exactly who it was, what they read and where they tried to go. Judges watch this screen from about 1.5 m away. It is the demo.

It shows only what actually arrived from the guard. Nothing is invented, faked or animated without a real event behind it.

You can build all of it today, on any OS, with no VM: `python3 bridge/bridge.py --fake` plays a realistic story.

## 2. Where it sits

```
 VM:  guard.py ──JSON lines──▶ bridge.py ──WebSocket :8765──┐
 or:  bridge.py --fake  (any machine) ──────────────────────┤
                                                            ▼
 host laptop:  Electron main.js ──bridge URL──▶ preload.js ──contextBridge──▶ renderer
                                                            renderer/app.js opens the WebSocket
                                                            renderer/index.html + style.css draw it
```

## 3. Files you own

- `dashboard/package.json`: Electron devDependency, `"start": "electron ."`
- `dashboard/main.js`: Electron main process
- `dashboard/preload.js`: exposes the bridge URL to the renderer
- `dashboard/renderer/index.html`: page structure, CSP
- `dashboard/renderer/app.js`: WebSocket client, state, rendering
- `dashboard/renderer/style.css`: styles
- `dashboard/docs/devansh.md`: this file (sections 6, 9, 10 only, during development)

Do not edit: `bridge/`, `guard/events.py` (Divyanshu), `guard/guard.py`, `guard/policy.py` (Hifza), `guard/bpf/` (Azaan), `demo/`, `scripts/`, `tests/` (Suyash).

## 4. What to build

### `main.js`

- One `BrowserWindow` with `webPreferences`: `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `preload: path.join(__dirname, "preload.js")`.
- `--kiosk` (and/or fullscreen) support for the stage.
- Bridge URL, first match wins: `--bridge=ws://...` argument, `SG_BRIDGE_URL` env var, default `ws://127.0.0.1:8765`. Hand it to `preload.js` (e.g. via `additionalArguments` in `webPreferences`).
- Load `renderer/index.html`.

### `preload.js`

- `contextBridge.exposeInMainWorld(...)` with the bridge URL only. Nothing else crosses into the renderer.

### `renderer/` (plain HTML/CSS/JS, no framework, no build step)

- Content-Security-Policy `<meta>` in `index.html`: `connect-src ws: wss:`, nothing remote otherwise (scripts and styles from `'self'` only).
- Bridge URL: the preload value if present; otherwise `?bridge=` from the page URL (browser fallback); otherwise `ws://127.0.0.1:8765`.
- The renderer opens the WebSocket itself.
- Auto-reconnect every 2 s on close or error.
- On `SNAPSHOT`: **replace** all state (mode, protect, allow, tagged, recent). This is what makes a mid-demo restart recover.
- On `GUARD_STATE`: update the guard-feeding indicator only. It is not a guard event; don't add it to the log.
- On any other event: append to the log; update the tagged list (`TAG`/`TAG_INHERIT` add, `UNTAG` remove); update policy from `READY`.

**The five panels (brief §6.4):**

1. **Status banner.** Calm green "Protected"; every event type not listed here leaves it green. On `BLOCK`: loud red for 5 s with `BLOCKED: <comm> (PID <tgid>) read <file> → tried <daddr>:<dport>`. On `WOULD_BLOCK` in audit mode: amber. On `ERROR`: red, showing the event's `message` instead of the BLOCKED text, and it stays until the next event arrives (sticky, not timed). If a field is null, omit that part of the text (no `file` → drop `read <file>`).
2. **Tagged processes.** Live list: comm, PID, file, inherited-from (`parent_tgid`), since. For inherited entries `comm` is the name at fork (usually the parent's, e.g. `python3` for a curl child); show it as-is.
3. **Event log.** Newest first, coloured by type. Keep the newest 100 entries.
4. **Policy panel.** Mode, protected files, allowlist (from `SNAPSHOT`/`READY`).
5. **Connection indicators, two separate ones.** *Bridge reachable*: WebSocket connected / reconnecting. *Guard feeding*: from `SNAPSHOT.guard_connected`, then each `GUARD_STATE` message. While the bridge is unreachable the guard state is unknown; show it as unknown, not as feeding.

**Look:** dark theme, high contrast, large type readable from 1.5 m. Plain and functional with clear hierarchy: the banner is the loudest thing, then tagged processes, then the log. No template-style gradients, glow effects or decorative animation. Colour carries meaning (green/amber/red, per-type log colours), so keep it consistent.

**Real data only:** render fields as they arrive. Never fake a value, a count or a transition that no event caused.

**Browser fallback:** `renderer/index.html` must work opened directly in a normal browser (`file://.../index.html?bridge=ws://<vm-ip>:8765`). That is the stage fallback if Electron breaks. So `app.js` must not depend on Electron APIs.

## 5. Contract excerpts

Contract excerpt (source of truth: ARCHITECTURE.md, section "Contract 4: Bridge WebSocket protocol"):

> - When a client connects, it first sends:
>   ```json
>   {"v":1,"type":"SNAPSHOT","mode":"enforce","guard_connected":true,"protect":[...],"allow":[...],
>    "tagged":[{"tgid":4421,"comm":"python3","file":"...","since":1760600000.1,"parent_tgid":null}],
>    "recent":[ ...last 50 events... ]}
>   ```
>   So a dashboard that restarts mid-demo recovers its full state.
> - Guard state: the bridge sends `{"v":1,"type":"GUARD_STATE","connected":false}` to every client on stdin EOF (guard gone), and `{"v":1,"type":"GUARD_STATE","connected":true}` when the guard feed reconnects. `SNAPSHOT` carries the current value as `"guard_connected"`. `--fake` always reports `true`. `GUARD_STATE` is a bridge message, not a guard event, so it is not added to `recent`.
> - Read-only feed. Ignore messages from clients.
> - `--host` defaults to `127.0.0.1` (pass `0.0.0.0` in the VM). A malformed stdin line is skipped and logged to stderr. A repeat `TAG` for an already-tagged tgid keeps its original `since`. Before `READY` arrives, `SNAPSHOT.mode` is `null`. On stdin EOF (guard gone) the bridge keeps running, serves the last state, and sends `GUARD_STATE` (below).

Contract excerpt (source of truth: ARCHITECTURE.md, section "Contract 3: Guard CLI and JSON event schema"):

```json
{"v":1,"ts":1760600000.123,"type":"BLOCK","hook":"connect","tgid":4421,"parent_tgid":null,
 "comm":"curl","file":"/home/demo/syscallguard/demo/project/.env",
 "family":"ipv4","daddr":"192.168.122.1","dport":9999,"mode":"enforce"}
```

| Field | Type | Notes |
|---|---|---|
| `v` | int | schema version, `1` |
| `ts` | float | Unix epoch seconds (convert from `ts_ns` using boot-time offset) |
| `type` | string | `READY` `TAG` `TAG_INHERIT` `ALLOW` `BLOCK` `WOULD_BLOCK` `UNTAG` `ERROR` |
| `hook` | string or null | `file_open` `connect` `sendmsg` `fork` `exit` |
| `tgid`, `parent_tgid` | int or null | |
| `comm` | string or null | process name; `null` on `READY`/`ERROR`. On `TAG_INHERIT` it is the name at fork time (usually the parent's); consumers must not rely on it |
| `file` | string or null | protected path resolved from `ino` |
| `family` | `"ipv4"`/`"ipv6"`/null | |
| `daddr` | string or null | formatted with `ipaddress` |
| `dport` | int or null | |
| `mode` | string | current mode |

The `READY` event also carries `"protect": [...]` and `"allow": [...]`. The `ERROR` event carries `"message": "..."`.

## 6. Your milestones

- [ ] **M5 Live dashboard** (G + U, fake: 19 Oct, real: 20 Oct): Electron shows `SNAPSHOT` state on connect; `BLOCK` turns the banner red within 1 s; restarting Electron mid-run recovers state

Dashboard side: everything working against `--fake` by 19 Oct; against the real guard in the VM by 20 Oct.

  - [ ] Electron (`^44.9.0`) tested on the stage laptop, before 21 Oct

**Start now:** the renderer in a plain browser, with hand-written JSON, even before `--fake` exists.
**Blocked by:** Divyanshu's `bridge.py --fake` for live testing (agree to have it on day one).
**You block:** Suyash and P (rehearsals, backup video, runbook screenshots).

## 7. How to run and test your part

Any OS, no VM:

```bash
python3 bridge/bridge.py --fake --port 8765           # terminal 1
cd dashboard && npm install && npm start               # terminal 2
```

Expected: both indicators show connected/feeding; the policy panel fills from `SNAPSHOT`; within ~10 s the story plays: python3 tagged, an ALLOW to 127.0.0.1:8080, a child tagged with inherited-from (comm `python3`, the name at fork), banner red for 5 s on the BLOCK by `curl` to 192.168.122.1:9999, then UNTAG clears the list.

Acceptance checks:

- Kill the bridge: the indicator shows reconnecting; restart it: reconnects within ~2 s.
- Guard gone: pipe a single line into the bridge (`printf '...' | python3 bridge/bridge.py`); after EOF the guard indicator shows not feeding while the bridge indicator stays connected.
- Quit and restart Electron mid-story: state comes back from `SNAPSHOT`.
- Browser fallback: open `dashboard/renderer/index.html?bridge=ws://127.0.0.1:8765` in Firefox/Chrome.

Against the VM:

```bash
SG_BRIDGE_URL=ws://<vm-ip>:8765 npm start
npm start -- --bridge=ws://<vm-ip>:8765 --kiosk
```

| If this happens | Check |
|---|---|
| Blank window, CSP errors in DevTools | CSP blocks inline script/style. Move them into `app.js` / `style.css`. |
| `require is not defined` in renderer | Correct: `nodeIntegration` is off. Don't use Node in the renderer. |
| Bridge URL is `undefined` | Preload not loaded (path) or not exposed via `contextBridge`. |
| Can't reach the VM bridge | Bridge started with `--host 0.0.0.0`? VM firewall port 8765 open? |
| Restart loses state | You're appending `SNAPSHOT` instead of replacing state with it. |
| Banner stays red | The 5 s timer isn't reset when a new `BLOCK` arrives, or isn't cleared. |
| Works in Electron, not in browser | `app.js` touches an Electron-only API. Read the URL from `?bridge=` fallback. |

## 8. Working with AI agents

Safety rules that apply here (from AGENTS.md):

- `dashboard/` must never import `bcc` or need root.
- Contracts are law: you consume Contracts 3 and 4. Need a new field? Ask for it in `docs/shared.md`; don't invent it in the renderer.
- Show real fields only. Never fake or animate data that didn't arrive.

Conventions: plain HTML/CSS/JS, no framework, no bundler, no CDN. Only `electron` as a devDependency. Escape every string from events before inserting into the DOM (`textContent`, not `innerHTML`): `comm` and file paths come from the system.

Common pitfalls: disabling `contextIsolation`/`sandbox` "to make it work"; remote fonts or scripts (CSP will block them, and the stage may be offline); small text; colour-only signals with no text label.

Commit format: `feat(dashboard): M5 banner and event log`, `fix(dashboard): reconnect loop`.

Start-here prompt to paste to an agent:

> I'm Devansh, Track U. Read AGENTS.md, docs/shared.md, dashboard/docs/devansh.md and ARCHITECTURE.md Contracts 3 and 4. Work only in dashboard/. Build against `python3 bridge/bridge.py --fake`. Keep contextIsolation/sandbox on, no framework, no remote resources, real data only. At the end, update only sections 6, 9 and 10 of my file.

## 9. Open questions

None open. Resolved 18 Oct: `ERROR` banner is sticky until the next event; guard state arrives via `GUARD_STATE` and `SNAPSHOT.guard_connected` (Contract 4).

## 10. Work log

- 2026-10-18: file created. Bootstrap only; dashboard files are stubs.
- 2026-10-18: docs updated with team decisions (TAG_INHERIT name not asserted, hook C emits no ALLOW, native IPv6 dropped, open questions resolved). See docs/shared.md.
- 2026-10-18: ERROR banner sticky; two indicators (bridge reachable, guard feeding) via GUARD_STATE (see docs/shared.md).
