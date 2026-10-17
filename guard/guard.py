# guard.py: SyscallGuard loader and main loop. Runs as root, inside the VM only.
# Track: G (Guard runtime & bridge)
# Contracts: ARCHITECTURE.md Contract 1 (maps), Contract 2 (policy), Contract 3 (CLI + JSON schema).
# Stdout is JSON lines only (flushed per line). All logs go to stderr.
#
# TODO (M1 Tagging):
#   - CLI: -p/--policy PATH, --mode audit|enforce (overrides file), --debug
#   - load policy via policy.py; exit 2 on error
#   - BPF(src_file=guard/bpf/syscallguard.bpf.c, cflags=["-I<abs path to guard/bpf>"])
#   - fill protected_inodes (st_ino -> index), allow_v4/allow_v6 (LPM keys), config[0].mode
#   - emit READY (with "protect" and "allow"), then poll the `events` ring buffer forever
#   - SIGINT/SIGTERM -> exit cleanly (hooks detach on exit)
# TODO (M3 Connect enforcement):
#   - verify enforce mode wiring end to end; emit ERROR events on runtime failures
