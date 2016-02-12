ifneq (,$(wildcard /usr/share/python/st2python/bin/python))
	PATH := /usr/share/python/st2python/bin:$(PATH)
endif

ifneq (,$(wildcard /etc/debian_version))
	DEBIAN := 1
	DESTDIR ?= $(CURDIR)/debian/$(ST2_COMPONENT)
else
	REDHAT := 1
endif

PKG_NAME := st2-auth-ldap
PKG_RELEASE ?= 1
PKG_VERSION := $(shell python setup.py --version 2>/dev/null)
WHEELSDIR ?= opt/stackstorm/share/wheels


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

# This is arch-dependent step and it must be called only are prepared
# environment, we will run it inside docker container. (from rpm spec)
install_deps:
	pip wheel --wheel-dir=$(DESTDIR)/$(WHEELSDIR) -r requirements.txt
