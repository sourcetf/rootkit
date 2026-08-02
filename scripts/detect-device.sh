#!/bin/bash
set -e
BOOTIMG="$1"

DEVICE=$(strings "$BOOTIMG" 2>/dev/null | grep -oE 'ro\.product\.device=[^[:space:]]+' | head -n1 | cut -d= -f2)

if [ -z "$DEVICE" ]; then
  DEVICE=$(strings "$BOOTIMG" 2>/dev/null | grep -oE 'ro\.build\.product=[^[:space:]]+' | head -n1 | cut -d= -f2)
fi

if [ -z "$DEVICE" ]; then
  DEVICE=$(dd if="$BOOTIMG" bs=1 skip=48 count=16 2>/dev/null | strings | head -n1 | tr -dc 'a-zA-Z0-9_-')
fi

if [ -z "$DEVICE" ]; then
  mkdir -p /tmp/dtb_extract
  python3 -c "
import struct
with open('$BOOTIMG','rb') as f:
    hdr = f.read(2048)
    if hdr[:8] == b'ANDROID!':
        ks = struct.unpack('<I', hdr[8:12])[0]
        ps = struct.unpack('<I', hdr[36:40])[0]
        f.seek(ps)
        with open('/tmp/dtb_extract/k.gz','wb') as o: o.write(f.read(ks))
    else:
        with open('/tmp/dtb_extract/k.gz','wb') as o: o.write(f.read())
" 2>/dev/null || true
  gzip -dc /tmp/dtb_extract/k.gz > /tmp/dtb_extract/kernel_raw 2>/dev/null || true
  if [ -f /tmp/dtb_extract/kernel_raw ]; then
    strings /tmp/dtb_extract/kernel_raw 2>/dev/null | grep -oE 'compatible[[:space:]]*=[[:space:]]*"[^"]+"' | head -n1 | sed 's/.*"\([^,]*\).*/\1/' | tr -dc 'a-zA-Z0-9_-' > /tmp/dtb_extract/dev.txt || true
    DEVICE=$(cat /tmp/dtb_extract/dev.txt 2>/dev/null)
  fi
fi

if [ -z "$DEVICE" ]; then
  DEVICE="unknown-$(sha256sum "$BOOTIMG" | cut -c1-8)"
fi

DEVICE=$(echo "$DEVICE" | tr '[:upper:]' '[:lower:]' | tr -dc 'a-z0-9_-')
echo "device=$DEVICE" >> "$GITHUB_OUTPUT"
echo "Detected device: $DEVICE"
