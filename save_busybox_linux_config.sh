#!/bin/sh

cd buildroot
make busybox-update-config BR2_EXTERNAL=../extern
make linux-update-defconfig BR2_EXTERNAL=../extern
