HOST_LIMINE_VERSION = 9.5.3
HOST_LIMINE_SITE = https://github.com/limine-bootloader/limine/releases/download/v$(HOST_LIMINE_VERSION)
HOST_LIMINE_SOURCE = limine-$(HOST_LIMINE_VERSION).tar.xz
HOST_LIMINE_LICENSE = BSD-2-Clause
HOST_LIMINE_LICENSE_FILES = COPYING
HOST_LIMINE_DEPENDENCIES = host-pkgconf host-nasm host-gzip host-genimage

HOST_LIMINE_CONF_OPTS = \
    --enable-bios \
    --enable-uefi-x86-64

HOST_LIMINE_AUTORECONF = YES

$(eval $(host-autotools-package))

