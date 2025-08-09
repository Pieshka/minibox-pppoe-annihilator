#!/bin/sh

cd buildroot
make list-defconfigs BR2_EXTERNAL=../
