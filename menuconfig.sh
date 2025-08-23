#!/bin/sh

cd buildroot
if [ "$1" = "" ]; then
    make menuconfig BR2_EXTERNAL=../extern
else
    make "$1-menuconfig" BR2_EXTERNAL=../extern
fi
