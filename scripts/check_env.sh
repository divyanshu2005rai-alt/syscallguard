#!/usr/bin/env bash
# check_env.sh: M0 environment check (Track D). Run inside the VM, no sudo needed.
# Prints PASS/FAIL per item, exits non-zero if any fail.

fails=0

check() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS  $desc"
    else
        echo "FAIL  $desc"
        fails=$((fails + 1))
    fi
}

echo "kernel: $(uname -r)"
echo "python: $(python3 --version 2>&1)"
echo

check "BPF LSM active (/sys/kernel/security/lsm contains bpf)" \
    grep -qw bpf /sys/kernel/security/lsm
check "BTF present (/sys/kernel/btf/vmlinux)" \
    test -e /sys/kernel/btf/vmlinux
check "kernel-devel-$(uname -r) installed" \
    rpm -q "kernel-devel-$(uname -r)"
check "python3: import bcc"        python3 -c "import bcc"
check "python3: import websockets" python3 -c "import websockets"
check "python3: import tomllib"    python3 -c "import tomllib"

echo
if [ "$fails" -eq 0 ]; then
    echo "All checks passed."
else
    echo "$fails check(s) failed."
    exit 1
fi
