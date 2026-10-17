# policy.py: parse and validate the SyscallGuard policy file.
# Track: G (Guard runtime & bridge)
# Contract: ARCHITECTURE.md Contract 2 (policy file).
#
# TODO (M1 Tagging):
#   - parse with tomllib
#   - mode in {"audit", "enforce"}; CLI --mode overrides the file
#   - every `protect` path is absolute and exists (os.stat follows symlinks -> protect the real file)
#   - every `allow` entry parses with ipaddress.ip_network(strict=False); split into v4/v6
#   - on any error: clear message to stderr, exit 2
#   - unit tests in tests/test_policy.py
