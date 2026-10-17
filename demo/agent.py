# agent.py: simulated AI agent that reads .env and "follows the README" injection.
# Track: D (Demo kit & verification). Python stdlib only (+ curl for --exfil curl).
# Contract: README/ARCHITECTURE demo flow; run unprivileged inside the VM.
#
# TODO (M3 Connect enforcement):
#   - CLI: --env PATH --api URL --target HOST:PORT --exfil MODE [--step]
#   - 1. read .env (gets tagged)  2. POST summary to --api (allowed)  3. exfil per MODE
#   - modes: direct, curl (subprocess, tests inheritance), b64, none
#   - print "BLOCKED by kernel (EPERM)" on PermissionError/EPERM; other errors verbatim
#   - --step waits for Enter between phases
# TODO (M4 Sendmsg):
#   - modes: udp (sendto), preconnect (connect before reading .env, send after), ipv6
