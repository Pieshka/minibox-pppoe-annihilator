#!/bin/sh
set -eu

# Configuration
BOARD_DIR="$(dirname $0)"
BOARD_NAME="$(basename ${BOARD_DIR})"
GENIMAGE_CFG="${BOARD_DIR}/genimage-nanopi-r2s.cfg"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"
ROOTPATH_TMP="$(mktemp -d)"

# Prepare trap
trap 'rm -rf "${ROOTPATH_TMP}"' EXIT

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
