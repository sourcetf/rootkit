#!/bin/bash
set -e
BOOTIMG="$1"

echo "=== Detecting device from $BOOTIMG ==="

# 方法1: 常见 prop strings（可能在 boot.img 的 padding 或 cmdline 中）
DEVICE=$(strings "$BOOTIMG" 2>/dev/null | grep -aoE 'ro\.product\.(device|name|board)=[^[:space:]]+' | head -n1 | cut -d= -f2)
echo "[*] Method 1 (strings prop): ${DEVICE:-<not found>}"

# 方法2: boot.img header name（仅 v0/v1/v2）
if [ -z "$DEVICE" ]; then
  NAME=$(dd if="$BOOTIMG" bs=1 skip=48 count=16 2>/dev/null | strings | head -n1 | tr -dc 'a-zA-Z0-9_-')
  if [ -n "$NAME" ] && [ "$NAME" != "unknown" ]; then
    DEVICE="$NAME"
    echo "[*] Method 2 (header name): $DEVICE"
  else
    echo "[*] Method 2 (header name): <not found or v3+>"
  fi
fi

# 方法3: 从 kernel 区域提取并搜索 DTB / strings
if [ -z "$DEVICE" ]; then
  echo "[*] Method 3: Extracting kernel from boot.img..."
  mkdir -p /tmp/dtb_extract
  
  python3 << PYEOF
import struct

with open("$BOOTIMG", 'rb') as f:
    hdr = f.read(4096)
    assert hdr[:8] == b'ANDROID!'
    
    kernel_size = struct.unpack('<I', hdr[8:12])[0]
    header_size = struct.unpack('<I', hdr[20:24])[0]
    
    if header_size == 1580:
        # v3/v4: kernel starts at header_size
        kernel_offset = header_size
    elif header_size == 1660:
        kernel_offset = header_size
    elif header_size == 0:
        page_size = struct.unpack('<I', hdr[36:40])[0]
        kernel_offset = page_size if page_size > 0 else 2048
    else:
        page_size = struct.unpack('<I', hdr[36:40])[0]
        kernel_offset = page_size if page_size > 0 else 2048
    
    print(f"[+] Kernel @ offset {kernel_offset}, size {kernel_size}")
    f.seek(kernel_offset)
    kernel = f.read(kernel_size)

    # Save
    with open('/tmp/dtb_extract/kernel', 'wb') as o:
        o.write(kernel)
    
    # Try identify compression
    first = kernel[:16]
    print(f"[+] First 16 bytes: {first.hex()}")
    
    # Search for DTB magic in kernel (appended dtb)
    magic = b'\xd0\x0d\xfe\xed'
    idx = kernel.rfind(magic)
    if idx >= 0:
        size = struct.unpack('>I', kernel[idx+4:idx+8])[0]
        with open('/tmp/dtb_extract/dtb', 'wb') as o:
            o.write(kernel[idx:idx+size])
        print(f"[+] Found DTB at kernel offset {idx}")
    else:
        print("[-] No DTB in kernel")
PYEOF

  if [ -f /tmp/dtb_extract/dtb ]; then
    # 从 DTB 提取 compatible（取第一个逗号前的板级名称）
    DEVICE=$(strings /tmp/dtb_extract/dtb 2>/dev/null | grep -oE ',[a-zA-Z0-9_-]+' | head -n1 | tr -d ',')
    echo "[*] Method 3a (DTB compatible): ${DEVICE:-<not found>}"
  fi
  
  if [ -z "$DEVICE" ] && [ -f /tmp/dtb_extract/kernel ]; then
    # 从 kernel 的 strings 中找 device prop（有些内核编译时硬编码了）
    DEVICE=$(strings /tmp/dtb_extract/kernel 2>/dev/null | grep -aoE 'ro\.product\.(device|name|board)=[^[:space:]]+' | head -n1 | cut -d= -f2)
    echo "[*] Method 3b (kernel strings): ${DEVICE:-<not found>}"
  fi
fi

# 方法4: 在整个 boot.img 中搜索 DTB（有些设备 dtb 在单独区域）
if [ -z "$DEVICE" ]; then
  echo "[*] Method 4: Full boot.img DTB search..."
  python3 << PYEOF
import struct
with open("$BOOTIMG", 'rb') as f:
    data = f.read()
    magic = b'\xd0\x0d\xfe\xed'
    idx = data.find(magic)
    if idx >= 0:
        size = struct.unpack('>I', data[idx+4:idx+8])[0]
        with open('/tmp/dtb_extract/dtb2', 'wb') as o:
            o.write(data[idx:idx+size])
        print(f"[+] Found DTB at boot.img offset {idx}")
    else:
        print("[-] No DTB in boot.img")
PYEOF
  if [ -f /tmp/dtb_extract/dtb2 ]; then
    DEVICE=$(strings /tmp/dtb_extract/dtb2 2>/dev/null | grep -oE ',[a-zA-Z0-9_-]+' | head -n1 | tr -d ',')
    echo "[*] Method 4 (DTB compatible): ${DEVICE:-<not found>}"
  fi
fi

# 方法5: cmdline / androidboot
if [ -z "$DEVICE" ]; then
  DEVICE=$(strings "$BOOTIMG" 2>/dev/null | grep -oE 'androidboot\.(device|hardware)=[^[:space:]]+' | head -n1 | cut -d= -f2)
  echo "[*] Method 5 (cmdline): ${DEVICE:-<not found>}"
fi

# Fallback
if [ -z "$DEVICE" ]; then
  DEVICE="unknown-$(sha256sum "$BOOTIMG" | cut -c1-8)"
  echo "[!] Fallback (hash): $DEVICE"
fi

DEVICE=$(echo "$DEVICE" | tr '[:upper:]' '[:lower:]' | tr -dc 'a-z0-9_-')
echo "[+] Final detected device: $DEVICE"
echo "device=$DEVICE" >> "$GITHUB_OUTPUT"
