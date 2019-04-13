include $(TOPDIR)/rules.mk

PKG_NAME:=CleanDNS
PKG_VERSION:=0.3
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

define Package/CleanDNS/conffiles
/etc/cleandns_chnroute.txt
/etc/config/cleandns
endef

define Package/CleanDNS/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/chnroute.txt $(1)/etc/cleandns_chnroute.txt
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/openwrt/files/cleandns.config $(1)/etc/config/cleandns
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/files/cleandns.init $(1)/etc/init.d/cleandns
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cleandns $(1)/usr/bin
endef

$(eval $(call BuildPackage,CleanDNS))
