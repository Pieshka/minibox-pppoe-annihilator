#!/bin/sh

# Load variables
BR2_MINIBOX_VERSION=$(grep -oP '^BR2_MINIBOX_VERSION="\K[^"]+' "$BR2_CONFIG" || echo "unknown")
BR2_MINIBOX_DEFAULT_WAN_INTERFACE=$(grep -oP '^BR2_MINIBOX_DEFAULT_WAN_INTERFACE="\K[^"]+' "$BR2_CONFIG" || echo "eth0")
BR2_MINIBOX_DEFAULT_LAN_INTERFACE=$(grep -oP '^BR2_MINIBOX_DEFAULT_LAN_INTERFACE="\K[^"]+' "$BR2_CONFIG" || echo "eth1")
BR2_MINIBOX_DEFAULT_IP=$(grep -oP '^BR2_MINIBOX_DEFAULT_IP="\K[^"]+' "$BR2_CONFIG" || echo "192.168.77.1")
BR2_MINIBOX_DEFAULT_MASK=$(grep -oP '^BR2_MINIBOX_DEFAULT_MASK="\K[^"]+' "$BR2_CONFIG" || echo "24")

# Write Minibox version file into /minibox
echo "minibox-${BR2_MINIBOX_VERSION}" > "${TARGET_DIR}/minibox"

# Write persistent configuration into /etc/minibox.static
echo "PPPOE_IF=\"${BR2_MINIBOX_DEFAULT_WAN_INTERFACE}\"" > "${TARGET_DIR}/etc/minibox.static"
echo "LAN_IF=\"${BR2_MINIBOX_DEFAULT_LAN_INTERFACE}\"" >> "${TARGET_DIR}/etc/minibox.static"
echo "DEFAULT_IP=\"${BR2_MINIBOX_DEFAULT_IP}/${BR2_MINIBOX_DEFAULT_MASK}\"" >> "${TARGET_DIR}/etc/minibox.static"
