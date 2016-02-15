SHELL := /bin/bash
PKG_NAME := st2-auth-ldap
PKG_RELEASE ?= 1
PKG_VERSION := $(shell python setup.py --version 2>/dev/null)
WHEELSDIR ?= opt/stackstorm/share/wheels

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

# This step is arch-dependent and must be called only on prepared environment,
# it's run inside stackstorm/buildpack container. Invoked from rpm spec.
install_deps:
	pip wheel --wheel-dir=$(DESTDIR)/$(WHEELSDIR) -r requirements.txt
	# Well welcome to enterprise (rhel).
	# Hardcore workaround to make wheel installable on any platform.
	cd $(DESTDIR)/$(WHEELSDIR); \
		ls -1 *-cp27mu-*.whl | while read f; do \
			mv $$f $$(echo $$f | sed "s/cp27mu/none/"); \
		done
