// app.js: dashboard renderer logic. Plain JS, no framework.
// Track: U (Dashboard)
// Contracts: ARCHITECTURE.md Contract 3 (event fields), Contract 4 (SNAPSHOT protocol).
//
// TODO (M5 Live dashboard):
//   - bridge URL from preload value, else ?bridge= query param, else ws://127.0.0.1:8765
//   - open WebSocket; auto-reconnect every 2 s; show connected/reconnecting
//   - SNAPSHOT -> replace all state (restart mid-demo must recover)
//   - banner: green "Protected"; red 5 s on BLOCK with
//     "BLOCKED: <comm> (PID <tgid>) read <file> -> tried <daddr>:<dport>"; amber on WOULD_BLOCK
//   - tagged list (comm, PID, file, inherited-from, since); event log newest first, coloured by type
//   - policy panel (mode, protect, allow) from SNAPSHOT/READY
//   - show real fields only; never fake data
