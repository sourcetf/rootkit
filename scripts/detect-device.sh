#!/bin/bash
set -e
BOOTIMG="$1"

echo "=== Detecting device from $BOOTIMG ==="

# 方法1: 常见 prop strings
DEVICE=$(strings "$BOOTIMG" 2>/dev/null | grep -aoE 'ro\.product\.(device|name|board)=[^[:space:]]+' | head -n1 | cut -d= -f2)
echo "[*] Method 1 (strings prop): ${DEVICE:-<not found>}"

# 方法2: boot.img header name
if [ -z "$DEVICE" ]; then
  DEVICE=$(dd if="$BOOTIMG" bs=1 skip=48 count=16 2>/dev/null | strings | head -n1 | tr -dc 'a-zA-Z0-9_-')
  echo "[*] Method 2 (header name): ${DEVICE:-<not found>}"
fi

# 方法3: 从 kernel 区域提取 DTB
if [ -z "$DEVICE" ]; then
  echo "[*] Method 3: Extracting kernel & DTB..."
  mkdir -p /tmp/dtb_extract
  
  python3 << PYEOF
import struct
with open("$BOOTIMG", 'rb') as f:
    header = f.read(4096)
    if header[:8] != b'ANDROID!':
        print("[-] Not a valid boot.img")
        exit(0)
    
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
    
    # Search DTB magic from end of kernel (appended dtb)
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
    DEVICE=$(strings /tmp/dtb_extract/dtb 2>/dev/null | grep -oE ',[a-zA-Z0-9_-]+' | head -n1 | tr -d ',')
    echo "[*] Method 3 (DTB compatible): ${DEVICE:-<not found>}"
  fi
fi

# 方法4: 在整个 boot.img 中搜索 DTB（dtb 可能在单独区域）
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
PYEOF
  if [ -f /tmp/dtb_extract/dtb2 ]; then
    DEVICE=$(strings /tmp/dtb_extract/dtb2 2>/dev/null | grep -oE ',[a-zA-Z0-9_-]+' | head -n1 | tr -d ',')
    echo "[*] Method 4 (DTB compatible): ${DEVICE:-<not found>}"
  fi
fi

# 方法5: cmdline
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
echo "[+] Final device: $DEVICE"
echo "device=$DEVICE" >> "$GITHUB_OUTPUT"
