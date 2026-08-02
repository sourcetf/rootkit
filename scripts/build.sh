#!/bin/bash
set -e
DEVICE="$1"

echo "Cloning CVE-2026-43499-root-KernelSU..."
git clone --depth 1 https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU.git jailbreak
cd jailbreak

echo "Generating target.h for $DEVICE..."
mkdir -p "src/targets/$DEVICE"
pip install -r tools/requirements.txt 2>/dev/null || true

GEN="python3 tools/generate_target.py --project $DEVICE --boot ../images/boot.img"
[ -f "../images/xbl_config.img" ] && GEN="$GEN --xbl-config ../images/xbl_config.img"
[ -f "../images/vendor_boot.img" ] && GEN="$GEN --mtk-vendor-boot ../images/vendor_boot.img"

$GEN || {
  echo "[!] Fallback to rodin template"
  TARGET_TEMPLATE=rodin $GEN --template-target rodin
}

echo "Building preload.so..."
make PROJECT="$DEVICE" -j$(nproc)

echo "Copying outputs..."
cp "build/$DEVICE/bin/preload.so" ../preload.so
cp "src/targets/$DEVICE/target.h" ../target.h
echo "Build complete."
