/*
 * sg_common.h: Contract 1 (kernel structs, constants). Owned by Track K.
 * Shared by syscallguard.bpf.c and mirrored by guard/events.py (ctypes).
 * Change only via a `contract:` commit that also updates ARCHITECTURE.md.
 */
#ifndef SG_COMMON_H
#define SG_COMMON_H

/* event types */
#define SG_EV_TAG          1
#define SG_EV_TAG_INHERIT  2
#define SG_EV_ALLOW        3
#define SG_EV_BLOCK        4
#define SG_EV_WOULD_BLOCK  5
#define SG_EV_UNTAG        6

/* hooks */
#define SG_HOOK_NONE       0
#define SG_HOOK_FILE_OPEN  1
#define SG_HOOK_CONNECT    2
#define SG_HOOK_SENDMSG    3
#define SG_HOOK_FORK       4
#define SG_HOOK_EXIT       5

/* modes (config map) */
#define SG_MODE_AUDIT      1
#define SG_MODE_ENFORCE    2

struct sg_tag_info {
    u64 ts_ns;          /* when tagged (bpf_ktime_get_ns) */
    u64 ino;            /* inode of the protected file that caused the tag */
    u32 parent_tgid;    /* 0 if tagged directly, else the tgid it inherited from */
    u32 _pad;
};

struct sg_event {
    u64 ts_ns;
    u64 ino;            /* protected file inode (from tag info), 0 if n/a */
    u32 type;           /* SG_EV_* */
    u32 hook;           /* SG_HOOK_* */
    u32 tgid;
    u32 parent_tgid;    /* TAG_INHERIT only */
    u16 family;         /* AF_INET=2, AF_INET6=10, 0 if n/a */
    u16 dport;          /* host byte order */
    u8  daddr[16];      /* IPv4 in first 4 bytes, network order */
    char comm[16];
};

struct sg_config { u32 mode; };

struct sg_lpm_v4 { u32 prefixlen; u8 addr[4]; };
struct sg_lpm_v6 { u32 prefixlen; u8 addr[16]; };

#endif
