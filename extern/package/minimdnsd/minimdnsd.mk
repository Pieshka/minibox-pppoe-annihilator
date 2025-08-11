################################################################################
#
# minimdnsd
#
################################################################################

MINIMDNSD_VERSION = dbff97c
MINIMDNSD_SITE = https://github.com/cnlohr/minimdnsd.git
MINIMDNSD_SITE_METHOD = git
MINIMDNSD_LICENSE = MIT
MINIMDNSD_LICENSE_FILES = LICENSE

ifeq ($(BR2_INET_IPV6),)
MINIMDNSD_CFLAGS += -DDISABLE_IPV6=1
endif

define MINIMDNSD_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) \
		-o $(@D)/minimdnsd $(@D)/minimdnsd.c
endef

define MINIMDNSD_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/minimdnsd $(TARGET_DIR)/usr/sbin/minimdnsd
	$(INSTALL) -D -m 0755 $(MINIMDNSD_PKGDIR)/S42minimdnsd \
		$(TARGET_DIR)/etc/init.d/S42minimdnsd
endef

$(eval $(generic-package))
