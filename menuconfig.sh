#!/bin/sh

cd buildroot

make menuconfig BR2_EXTERNAL=../extern
