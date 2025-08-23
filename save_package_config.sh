#!/bin/sh

# Check if we have buildroot config
if [ ! -f "buildroot/.config" ]; then
    echo "No buildroot config detected! Use set_defconfig.sh to apply a defconfig of your choice"
    exit 1
fi

# Get info about packages
LINUX_KERNEL=$(grep -oP '^BR2_LINUX_KERNEL=\K.*' "buildroot/.config" || echo "n")
BUSYBOX=$(grep -oP '^BR2_PACKAGE_BUSYBOX=\K.*' "buildroot/.config" || echo "n")
UBOOT=$(grep -oP '^BR2_TARGET_UBOOT=\K.*' "buildroot/.config" || echo "n")

# Change directory
cd buildroot

# Save kernel config if exist
if [ "$LINUX_KERNEL" = "y" ]; then
    make linux-update-defconfig BR2_EXTERNAL=../extern
fi

# Save busybox config if exist
if [ "$BUSYBOX" = "y" ]; then
    make busybox-update-config BR2_EXTERNAL=../extern
fi

# Save uboot config if exist
if [ "$UBOOT" = "y" ]; then
    make uboot-update-defconfig BR2_EXTERNAL=../extern
fi

