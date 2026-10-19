#!/usr/bin/env python3
"""THROWAWAY test loader for hook A (Track K). Not guard.py. Delete once Hifza's loader lands.

Run in the VM from the repo root:
    sudo python3 scratch/azaan/load_hook_a.py [--mode audit|enforce] [--allow CIDR ...] [FILE ...]
Default protected file: demo/project/.env; default allow: 127.0.0.0/8 and ::1/128; default mode:
audit. Always fills `config`: check_dest blocks unless mode == AUDIT, so an empty config enforces.
Prints one JSON line per event on stdout, logs on stderr. Ctrl-C detaches every hook.
"""
import argparse
import ctypes
import ipaddress
import json
import os
import struct
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BPF_DIR = os.path.join(REPO, "guard", "bpf")
TYPES = {1: "TAG", 2: "TAG_INHERIT", 3: "ALLOW", 4: "BLOCK", 5: "WOULD_BLOCK", 6: "UNTAG"}
HOOKS = {1: "file_open", 2: "connect", 3: "sendmsg", 4: "fork", 5: "exit"}
EVENT = "<QQIIIIHH16s16s"   # struct sg_event; C sizeof is 72 (tail padding)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def main():
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 scratch/azaan/load_hook_a.py")
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("audit", "enforce"), default="audit")
    ap.add_argument("--allow", action="append", type=lambda c: ipaddress.ip_network(c, strict=False))
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()
    allow = args.allow or [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    paths = [os.path.realpath(p) for p in (args.files or [os.path.join(REPO, "demo/project/.env")])]
    inode_paths = {os.stat(p).st_ino: p for p in paths}

    from bcc import BPF
    b = BPF(src_file=os.path.join(BPF_DIR, "syscallguard.bpf.c"), cflags=["-I" + BPF_DIR, "-fms-extensions"])  # 7.x headers need it, see docs/shared.md
    for net in allow:
        t = b["allow_v4" if net.version == 4 else "allow_v6"]
        k = t.Key()
        k.prefixlen = net.prefixlen
        k.addr = type(k.addr)(*net.network_address.packed)
        t[k] = t.Leaf(1)
    cfg = b["config"]
    cfg[cfg.Key(0)] = cfg.Leaf({"audit": 1, "enforce": 2}[args.mode])
    log(f"mode={args.mode} allow={' '.join(map(str, allow))}")
    # Protect last: nothing gets tagged until mode and allowlist are in place.
    prot = b["protected_inodes"]
    for i, ino in enumerate(inode_paths):
        prot[prot.Key(ino)] = prot.Leaf(i)
    boot_epoch = time.time() - time.monotonic()   # bpf_ktime_get_ns is CLOCK_MONOTONIC
    for ino, p in inode_paths.items():
        log(f"loaded; protecting ino={ino} {p}")

    def on_event(_ctx, data, size):
        ts, ino, typ, hook, tgid, ptgid, fam, dport, daddr, comm = struct.unpack_from(EVENT, ctypes.string_at(data, size))
        addr = {2: lambda: str(ipaddress.IPv4Address(daddr[:4])), 10: lambda: str(ipaddress.IPv6Address(daddr))}.get(fam)
        print(json.dumps({
            "type": TYPES.get(typ, typ), "hook": HOOKS.get(hook), "tgid": tgid,
            "parent_tgid": ptgid or None, "comm": comm.split(b"\0", 1)[0].decode(errors="replace"),
            "ino": ino, "file": inode_paths.get(ino), "ts": round(boot_epoch + ts / 1e9, 3),
            "daddr": addr() if addr else None, "dport": dport if addr else None, "mode": args.mode,
        }), flush=True)

    b["events"].open_ring_buffer(on_event)
    log("watching; Ctrl-C to stop")
    try:
        while True:
            b.ring_buffer_poll()
    except KeyboardInterrupt:
        log("detached")


if __name__ == "__main__":
    main()
