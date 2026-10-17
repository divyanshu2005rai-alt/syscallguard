# events.py: decode `struct sg_event` from the ring buffer into Contract 3 JSON dicts.
# Track: G (Guard runtime & bridge)
# Contracts: ARCHITECTURE.md Contract 1 (struct sg_event, SG_EV_*/SG_HOOK_* constants),
#            Contract 3 (JSON event schema).
#
# TODO (M1 Tagging):
#   - ctypes mirror of struct sg_event (must match sg_common.h byte for byte)
#   - map type/hook ints to strings; ino -> protected path; comm -> str
#   - ts_ns (monotonic since boot) -> Unix epoch seconds via boot-time offset
# TODO (M3/M4):
#   - family 2/10 -> "ipv4"/"ipv6"; daddr bytes -> ipaddress string; dport int
