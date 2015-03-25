#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=apd
PKG_RELEASE:=1

PKG_LICENSE:=GPLv2 GPLv2+
PKG_LICENSE_FILES:=

include $(INCLUDE_DIR)/package.mk

define Package/apd
  SECTION:=utils
  CATEGORY:=Base system
  DEPENDS:=+libubox +libblobmsg-json +libjson-c +libuci +libubus
  TITLE:=morewifi heartbeat daemon
endef

define Package/apd/description
 This package contains an daemon to heartbeat with morewifi cloud server
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/apd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/apd.init $(1)/etc/init.d/apd
	$(INSTALL_DIR) $(1)/usr/share/
	$(INSTALL_DATA) ./src/apc.sp $(1)/usr/share/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/ap.conf $(1)/etc/config/ap
endef

$(eval $(call BuildPackage,apd))
