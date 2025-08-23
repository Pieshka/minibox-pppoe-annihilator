#!/bin/sh

cd buildroot

make uboot-menuconfig BR2_EXTERNAL=../extern
