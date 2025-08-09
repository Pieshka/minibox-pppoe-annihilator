#!/bin/sh

if [ -z "$1" ]; then
	echo "Defconfig name not specified"
	exit 1
fi

if [ ! -f "extern/configs/$1_defconfig" ]; then
	echo "Specified defconfig does not exist"
	exit 1
fi

cd buildroot
make savedefconfig BR2_EXTERNAL=../extern BR2_DEFCONFIG="../extern/configs/$1_defconfig"
