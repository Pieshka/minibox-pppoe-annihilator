#!/bin/sh
set -eu

# Configuration
BOARD_DIR="$(dirname $0)"
BOARD_NAME="$(basename ${BOARD_DIR})"
GENIMAGE_TEMPLATE="${BOARD_DIR}/genimage-nanopi-r2s.cfg.in"
GENIMAGE_CFG="${BINARIES_DIR}/genimage.cfg"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"
ROOTPATH_TMP="$(mktemp -d)"
KERNEL="${BINARIES_DIR}/Image"
FDT="${BINARIES_DIR}/rk3328-nanopi-r2s.dtb"
BOOTCMD_TEMPLATE="${BOARD_DIR}/boot-nanopi-r2s.cmd.in"
BOOTCMD="${BINARIES_DIR}/boot.cmd"
BOOTSCRIPT="${BINARIES_DIR}/boot.scr"

# Prepare boot.cmd
# for now we are just copying template
cp "${BOOTCMD_TEMPLATE}" "${BOOTCMD}"

# Generate boot.scr
mkimage -A arm64 -T script -C none -n "Minibox" \
    -d "${BOOTCMD}" "${BOOTSCRIPT}"

# Prepare genimage.cfg
BOOTFILES="${KERNEL} ${BOOTSCRIPT} ${FDT}"
BOOTSIZE=$(du -cb ${BOOTFILES} | tail -n1 | cut -f1)
BOOTSIZE=$(( (BOOTSIZE + 1024*1024 - 1) / (1024*1024) * 1024*1024 ))
sed "s/@BOOT_SIZE@/${BOOTSIZE}/" "${GENIMAGE_TEMPLATE}" > "${GENIMAGE_CFG}"

# Prepare trap
trap 'rm -rf "${ROOTPATH_TMP}" "${GENIMAGE_CFG}" "${BOOTCMD}" "${BOOTSCRIPT}"' EXIT

# Run genimage
rm -rf "${GENIMAGE_TMP} ${ROOTPATH_TMP}"
genimage \
    --rootpath "${ROOTPATH_TMP}" \
    --tmppath "${GENIMAGE_TMP}" \
    --inputpath "${BINARIES_DIR}" \
    --outputpath "${BINARIES_DIR}" \
    --config "${GENIMAGE_CFG}" \

# Rename and compress sdcard.img
DATE=$(date +%Y-%m-%d)
IMAGE_NAME="minibox"
if [ -n "$2" ]; then
    IMAGE_NAME="$2"
fi
OUTPUT_PREFIX="${DATE}-${IMAGE_NAME}-arm64"
mv "${BINARIES_DIR}/sdcard.img" "${BINARIES_DIR}/${OUTPUT_PREFIX}.img"
rm "${BINARIES_DIR}/${OUTPUT_PREFIX}.img.xz" || true
xz -9 -T0 -v "${BINARIES_DIR}/${OUTPUT_PREFIX}.img"

exit 0
