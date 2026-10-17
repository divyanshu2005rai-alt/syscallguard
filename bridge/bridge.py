# bridge.py: stdin JSON lines -> WebSocket broadcast, with state snapshot for new clients.
# Track: G (Guard runtime & bridge). Never imports bcc, never needs root.
# Contracts: ARCHITECTURE.md Contract 3 (input events), Contract 4 (WebSocket protocol).
#
# TODO (M5 Live dashboard, fake by 19 Oct):
#   - CLI: --host, --port (default 8765), --fake
#   - asyncio + websockets; broadcast each input line unchanged to every client
#   - state: mode, protect, allow, tagged set (TAG/TAG_INHERIT add, UNTAG remove), last 50 events
#   - on client connect send SNAPSHOT first; ignore client messages
#   - --fake: loop READY -> TAG(python3) -> ALLOW 127.0.0.1:8080 -> TAG_INHERIT(curl)
#             -> BLOCK 192.168.122.1:9999 -> UNTAG, every ~10 s
# TODO (M5 real, 20 Oct): run piped from guard.py inside the VM
