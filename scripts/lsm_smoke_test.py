#!/usr/bin/env python3
"""lsm_smoke_test.py: M0 check that bcc can load a BPF LSM program (Track D).

Run as root inside the VM:  sudo python3 scripts/lsm_smoke_test.py
Loads a file_open LSM probe that trace_printks on every call and always
returns 0 (never denies), prints 5 trace lines, exits 0. The probe detaches
when this process exits.
"""
import os
import sys

HINT = "hint: check lsm list contains bpf; check kernel-devel matches uname -r"

PROG = r"""
LSM_PROBE(file_open, struct file *file)
{
    bpf_trace_printk("sg smoke: file_open\n");
    return 0;
}
"""


def main():
    if os.geteuid() != 0:
        print("must run as root: sudo python3 scripts/lsm_smoke_test.py", file=sys.stderr)
        return 1

    try:
        from bcc import BPF
        b = BPF(text=PROG)
    except Exception as e:
        print(f"failed to load LSM probe: {e}", file=sys.stderr)
        print(HINT, file=sys.stderr)
        return 1

    print("LSM probe loaded. First 5 trace lines:")
    for _ in range(5):
        # Open a file ourselves so there is always at least one hit to read.
        with open("/etc/hostname"):
            pass
        line = b.trace_readline()
        print(" ", line.decode(errors="replace") if isinstance(line, bytes) else line)

    print("OK: BPF LSM works.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
