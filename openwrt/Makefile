include $(TOPDIR)/rules.mk

PKG_NAME:=CleanDNS
PKG_VERSION:=0.4.1
PKG_RELEASE:=master
PKG_BUILD_PARALLEL:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/GangZhuo/CleanDNS.git
PKG_SOURCE_VERSION:=2172948b21c9a0d5cfaea56016bc15503487de7c
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/CleanDNS
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Non-polluting DNS.
	URL:=https://github.com/GangZhuo/CleanDNS
	MAINTAINER:=Gang Zhuo <gang.zhuo@gmail.com>
endef

define Package/CleanDNS/description
Non-polluting DNS. Forward DNS requests with ECS(edns-client-subnet) support.
endef

define Package/CleanDNS/conffiles
/etc/cleandns_chnroute.txt
/etc/config/cleandns
endef

define Package/CleanDNS/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cleandns $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/cleandns.init $(1)/etc/init.d/cleandns
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) files/cleandns.chnroute $(1)/etc/cleandns_chnroute.txt
	$(INSTALL_DATA) files/cleandns.chnroute6 $(1)/etc/cleandns_chnroute6.txt
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) files/cleandns.config $(1)/etc/config/cleandns
endef

$(eval $(call BuildPackage,CleanDNS))
