#!/bin/sh

cd buildroot
make uboot-update-defconfig BR2_EXTERNAL=../extern
