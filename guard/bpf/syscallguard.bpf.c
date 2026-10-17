/*
 * syscallguard.bpf.c: all SyscallGuard eBPF hooks and maps (compiled by bcc at load time).
 * Track: K (Kernel enforcement)
 * Contract: ARCHITECTURE.md Contract 1 (sg_common.h structs, map names) and the Hooks /
 *           Decision logic sections. Map names are part of the contract: guard.py looks them up.
 *
 * TODO (M1 Tagging):
 *   - #include "sg_common.h"; declare maps protected_inodes, tagged, allow_v4, allow_v6,
 *     config, events exactly as in ARCHITECTURE.md
 *   - Hook A: LSM_PROBE(file_open): tag tgid if inode is protected, emit TAG, always return 0
 * TODO (M2 Inheritance & cleanup):
 *   - Hook D: RAW_TRACEPOINT_PROBE(sched_process_fork): inherit tag to new processes, emit TAG_INHERIT
 *   - Hook E: TRACEPOINT_PROBE(sched, sched_process_exit): leader exit -> delete tag, emit UNTAG
 * TODO (M3 Connect enforcement):
 *   - check_dest() per ARCHITECTURE.md (untagged fast path = one map lookup; v4-mapped v6 -> v4)
 *   - Hook B: LSM_PROBE(socket_connect)
 * TODO (M4 Sendmsg):
 *   - Hook C: LSM_PROBE(socket_sendmsg): msg_name if set, else connected peer from sk_common
 * TODO (S1 Stretch, after M7): socket_create denies AF_PACKET/SOCK_RAW for tagged processes
 */
