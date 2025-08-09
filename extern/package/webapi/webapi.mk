WEBAPI_SITE = $(BR2_EXTERNAL_MINIBOX_PATH)/package/webapi/src
WEBAPI_SITE_METHOD = local
WEBAPI_LICENSE = MIT

# Technically we need a web server to execute,
# but I don't want to enforce any particular one.
WEBAPI_DEPENDENCIES =
WEBAPI_INSTALL_TARGET = YES

define WEBAPI_BUILD_CMDS
	$(MAKE) -C $(@D) CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"
endef

define WEBAPI_INSTALL_TARGET_CMDS
	$(MAKE) -C $(@D) DESTDIR=$(TARGET_DIR) install
endef

$(eval $(generic-package))
