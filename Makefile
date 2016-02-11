PKG_NAME := st2-auth-ldap
PKG_RELEASE ?= 1
PKG_VERSION ?= 0.1
WHEELSDIR ?= opt/stackstorm/share/wheels

ifneq (,$(wildcard /usr/share/python/st2python/bin/python))
	PATH := /usr/share/python/st2python/bin:$(PATH)
endif

ifneq (,$(wildcard /etc/debian_version))
	DEBIAN := 1
	DESTDIR ?= $(CURDIR)/debian/$(ST2_COMPONENT)
else
	REDHAT := 1
endif

.PHONY: all install changelog install_wheel
all:

install: changelog install_wheel

changelog: .stamp-changelog
.stamp-changelog:
ifeq ($(DEBIAN),1)
	debchange -v $(PKG_VERSION)-$(PKG_RELEASE) -M "$(PKG_NAME) $(PKG_VERSION)-$(PKG_RELEASE) release"
endif
	touch $@

install_wheel:
	install -d $(DESTDIR)/$(WHEELSDIR)
	python setup.py bdist_wheel -d $(DESTDIR)/$(WHEELSDIR)
