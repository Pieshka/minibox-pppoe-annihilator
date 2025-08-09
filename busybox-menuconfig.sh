#!/bin/sh

cd buildroot

make busybox-menuconfig BR2_EXTERNAL=../extern
