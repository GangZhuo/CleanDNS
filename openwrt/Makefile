include $(TOPDIR)/rules.mk

PKG_NAME:=CleanDNS
PKG_VERSION:=0.2
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_URL:=https://github.com/GangZhuo/CleanDNS/archive
#PKG_SOURCE:=$(PKG_VERSION).tar.gz
#PKG_BUILD_DEPENDS:=

#PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/CleanDNS
	SECTION:=net
	CATEGORY:=Network
	TITLE:=CleanDNS
	URL:=https://github.com/GangZhuo/CleanDNS
	MAINTAINER:=Gang Zhuo <gang.zhuo@gmail.com>
	DEPENDS:=
endef

define Package/CleanDNS/description
	Forward DNS requests.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r ../* $(PKG_BUILD_DIR)
endef

define Package/CleanDNS/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cleandns $(1)/usr/bin
endef

$(eval $(call BuildPackage,CleanDNS))
