#!/bin/sh
set -eu

# Configuration
BOARD_DIR="$(dirname $0)"
BOARD_NAME="$(basename ${BOARD_DIR})"
GENIMAGE_TEMPLATE="${BOARD_DIR}/genimage-x86_64.cfg.in"
GENIMAGE_CFG="${BINARIES_DIR}/genimage.cfg"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"
ROOTPATH_TMP="$(mktemp -d)"
LIMINE_CONFIG_TEMPLATE="${BOARD_DIR}/limine.conf.in"
LIMINE_CONFIG="${BINARIES_DIR}/limine.conf"
LIMINE_BIN="${HOST_DIR}/bin/limine"
LIMINE_SHARE="${HOST_DIR}/share/limine"
LIMINE_BIOS="${LIMINE_SHARE}/limine-bios.sys"
LIMINE_UEFI="${LIMINE_SHARE}/BOOTX64.EFI"
KERNEL="${BINARIES_DIR}/bzImage"
ROOTFS="${BINARIES_DIR}/rootfs.ext4"

# Check if we have limine, if not - fail silently
# but continue building process
if [ ! -f "$LIMINE_BIN" ]; then
    echo "No limine detected. Disk image will not be built"
    exit 0
fi

# But if we have limine, check if we got rootfs and kernel
# and stop the building process
for f in "$KERNEL" "$ROOTFS"; do
    if [ ! -f "$f" ]; then
        echo "Cannot find $f file"
        exit 1
    fi
done

# Calculate boot files total size
BOOT_SIZE_BYTES=$(du -bc \
    "$KERNEL" \
    "$LIMINE_BIOS" \
    "$LIMINE_UEFI" \
    "$LIMINE_CONFIG_TEMPLATE" \
    | awk '/total/ { print $1 }')

# Calculate boot part size +2MB
BOOT_SIZE_MB=$(( (BOOT_SIZE_BYTES + 2 * 1024 * 1024) / 1024 / 1024))
BOOT_SIZE_STR="${BOOT_SIZE_MB}M"

# Generate random UUID for GPT partitions
ROOTFS_UUID=$(cat /proc/sys/kernel/random/uuid)
BOOT_UUID=$(cat /proc/sys/kernel/random/uuid)

# Generate genimage configuration
sed -e "s|@BOOT_PARTUUID@|${BOOT_UUID}|" \
    -e "s|@ROOT_PARTUUID@|${ROOTFS_UUID}|" \
    -e "s|@BOOT_PART_SIZE@|${BOOT_SIZE_STR}|" \
    "${GENIMAGE_TEMPLATE}" > "${GENIMAGE_CFG}"

# Generate limine configuration
sed -e "s|@ROOT_PARTUUID@|${ROOTFS_UUID}|" \
    "${LIMINE_CONFIG_TEMPLATE}" > "${LIMINE_CONFIG}"

# Prepare boot partition structure
trap 'rm -rf "${ROOTPATH_TMP}" "${TMP_BOOT}" "${GENIMAGE_CFG}" "${LIMINE_CONFIG}"' EXIT
TMP_BOOT="${BINARIES_DIR}/boot"
rm -rf "${TMP_BOOT}"
mkdir -p "${TMP_BOOT}/EFI/BOOT"

cp "$LIMINE_CONFIG" "${TMP_BOOT}/"
cp "$LIMINE_BIOS" "${TMP_BOOT}/"
cp "$KERNEL" "${TMP_BOOT}/"
cp "$LIMINE_UEFI" "${TMP_BOOT}/EFI/BOOT/"

# Run genimage
rm -rf "${GENIMAGE_TMP}"
genimage \
    --rootpath "${ROOTPATH_TMP}" \
    --tmppath "${GENIMAGE_TMP}" \
    --inputpath "${BINARIES_DIR}" \
    --outputpath "${BINARIES_DIR}" \
    --config "${GENIMAGE_CFG}" \

# Install limine onto the image
$LIMINE_BIN bios-install "${BINARIES_DIR}/disk.img"

# Clean
rm -rf "${ROOTPATH_TMP}" "${TMP_BOOT}" "${GENIMAGE_CFG}" "${LIMINE_CONFIG}"

# Rename and compress disk.img
DATE=$(date +%Y-%m-%d)
IMAGE_NAME="minibox"
if [ -n "$2" ]; then
    IMAGE_NAME="$2"
fi
OUTPUT_PREFIX="${DATE}-${IMAGE_NAME}-x86_64"
mv "${BINARIES_DIR}/disk.img" "${BINARIES_DIR}/${OUTPUT_PREFIX}.img"
rm "${BINARIES_DIR}/${OUTPUT_PREFIX}.img.xz" || true
xz -9 -T0 -v "${BINARIES_DIR}/${OUTPUT_PREFIX}.img"

exit 0
