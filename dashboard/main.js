// main.js: Electron main process for the SyscallGuard dashboard.
// Track: U (Dashboard)
// Contract: ARCHITECTURE.md "Dashboard (Track U)"; consumes Contract 4 via the renderer.
//
// TODO (M5 Live dashboard):
//   - one BrowserWindow: contextIsolation true, nodeIntegration false, sandbox true
//   - --kiosk / fullscreen support
//   - bridge URL: SG_BRIDGE_URL env or --bridge=ws://... (default ws://127.0.0.1:8765),
//     handed to preload.js
//   - load renderer/index.html
