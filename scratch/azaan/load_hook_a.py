#!/usr/bin/env python3
"""THROWAWAY test loader for hook A (Track K). Not guard.py. Delete once Hifza's loader lands.

Run in the VM from the repo root:  sudo python3 scratch/azaan/load_hook_a.py [FILE ...]
Default protected file: demo/project/.env. Prints one JSON line per event on stdout,
logs on stderr. Ctrl-C detaches every hook.
"""
import ctypes
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
    paths = [os.path.realpath(p) for p in (sys.argv[1:] or [os.path.join(REPO, "demo/project/.env")])]
    inode_paths = {os.stat(p).st_ino: p for p in paths}

    from bcc import BPF
    b = BPF(src_file=os.path.join(BPF_DIR, "syscallguard.bpf.c"), cflags=["-I" + BPF_DIR, "-fms-extensions"])  # 7.x headers need it, see docs/shared.md
    prot = b["protected_inodes"]
    for i, ino in enumerate(inode_paths):
        prot[prot.Key(ino)] = prot.Leaf(i)
    boot_epoch = time.time() - time.monotonic()   # bpf_ktime_get_ns is CLOCK_MONOTONIC
    for ino, p in inode_paths.items():
        log(f"loaded; protecting ino={ino} {p}")

    def on_event(_ctx, data, size):
        ts, ino, typ, hook, tgid, ptgid, _fam, _dport, _daddr, comm = struct.unpack_from(EVENT, ctypes.string_at(data, size))
        print(json.dumps({
            "type": TYPES.get(typ, typ), "hook": HOOKS.get(hook), "tgid": tgid,
            "parent_tgid": ptgid or None, "comm": comm.split(b"\0", 1)[0].decode(errors="replace"),
            "ino": ino, "file": inode_paths.get(ino), "ts": round(boot_epoch + ts / 1e9, 3),
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
