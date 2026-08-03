#!/bin/bash
set -e
BOOTIMG="$1"

echo "=== Detecting device from $BOOTIMG ==="

# 方法1: strings 找常见 prop（有些设备确实在 boot.img 里）
DEVICE=$(strings "$BOOTIMG" 2>/dev/null | grep -aoE 'ro\.product\.(device|name|board)=[^[:space:]]+' | head -n1 | cut -d= -f2)
echo "[*] Method 1 (strings prop): ${DEVICE:-<not found>}"

# 方法2: boot.img header name 字段（16字节 @ offset 0x30）
if [ -z "$DEVICE" ]; then
  DEVICE=$(dd if="$BOOTIMG" bs=1 skip=48 count=16 2>/dev/null | strings | head -n1 | tr -dc 'a-zA-Z0-9_-')
  echo "[*] Method 2 (header name): ${DEVICE:-<not found>}"
fi

# 方法3: 从 dtb 提取 compatible（最可靠）
if [ -z "$DEVICE" ]; then
  echo "[*] Method 3: Extracting DTB..."
  mkdir -p /tmp/dtb_extract
  
  # 用 python 提取 kernel 镜像（支持变量展开）
  python3 << PYEOF
import struct
with open("$BOOTIMG", 'rb') as f:
    hdr = f.read(2048)
    if hdr[:8] == b'ANDROID!':
        ks = struct.unpack('<I', hdr[8:12])[0]
        ps = struct.unpack('<I', hdr[36:40])[0]
        f.seek(ps)
        with open('/tmp/dtb_extract/k.gz', 'wb') as o:
            o.write(f.read(ks))
    else:
        f.seek(0)
        with open('/tmp/dtb_extract/k.gz', 'wb') as o:
            o.write(f.read())
PYEOF

  # 尝试解压 kernel
  for cmd in "gzip -dc" "lz4 -dc" "zstd -dc" "xz -dc"; do
    if $cmd /tmp/dtb_extract/k.gz > /tmp/dtb_extract/kernel_raw 2>/dev/null; then
      [ -s /tmp/dtb_extract/kernel_raw ] && { echo "[+] Decompressed kernel with $cmd"; break; }
    fi
  done

  if [ -s /tmp/dtb_extract/kernel_raw ]; then
    # 搜索 DTB magic (0xd00dfeed) 并提取
    python3 << PYEOF
import struct
with open('/tmp/dtb_extract/kernel_raw', 'rb') as f:
    data = f.read()
    magic = b'\xd0\x0d\xfe\xed'
    idx = data.find(magic)
    if idx >= 0:
        size = struct.unpack('>I', data[idx+4:idx+8])[0]
        with open('/tmp/dtb_extract/dtb', 'wb') as o:
            o.write(data[idx:idx+size])
        print(f'[+] Found DTB at offset {idx}, size {size}')
    else:
        print('[-] DTB magic not found in kernel')
PYEOF

    if [ -f /tmp/dtb_extract/dtb ]; then
      # 从 dtb 提取 compatible 字符串（取第一个逗号前的部分）
      DEVICE=$(strings /tmp/dtb_extract/dtb 2>/dev/null | grep -oE ',[a-zA-Z0-9_-]+' | head -n1 | tr -d ',')
      echo "[*] Method 3 (DTB compatible): ${DEVICE:-<not found>}"
    fi
  fi
fi

# 方法4: 从 kernel 的 __efistub 或内置 cmdline 找
if [ -z "$DEVICE" ]; then
  DEVICE=$(strings "$BOOTIMG" 2>/dev/null | grep -oE 'androidboot\.device=[^[:space:]]+' | head -n1 | cut -d= -f2)
  echo "[*] Method 4 (cmdline): ${DEVICE:-<not found>}"
fi

# 方法5: hash fallback
if [ -z "$DEVICE" ]; then
  DEVICE="unknown-$(sha256sum "$BOOTIMG" | cut -c1-8)"
  echo "[!] Method 5 (hash fallback): $DEVICE"
fi

DEVICE=$(echo "$DEVICE" | tr '[:upper:]' '[:lower:]' | tr -dc 'a-z0-9_-')
echo "[+] Final detected device: $DEVICE"
echo "device=$DEVICE" >> "$GITHUB_OUTPUT"
