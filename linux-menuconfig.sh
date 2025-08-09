#!/bin/sh

cd buildroot

make linux-menuconfig BR2_EXTERNAL=../extern
