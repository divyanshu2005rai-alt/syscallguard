# attack_matrix.py: privileged end-to-end attack matrix. VM only:
#   sudo python3 tests/attack_matrix.py --target 192.168.122.1:9999
# Track: D (Demo kit & verification)
# Contracts: ARCHITECTURE.md Contract 3 (expects BLOCK/ALLOW events); README "What it blocks".
#
# TODO (M6 Attack matrix):
#   - one case per "Blocked" row: direct, curl opens file, child curl/nc/python, b64, any port,
#     ipv6 + v4-mapped v6, udp sendto, preconnect then send
#   - controls: untagged process reaches the attacker; tagged process reaches allowlisted 127.0.0.1
#   - assert EPERM specifically (not just "failed"); attacker log shows 0 bytes
