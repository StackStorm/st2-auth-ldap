SHELL := /bin/bash
PKG_NAME := st2-auth-ldap
PKG_RELEASE ?= 1
PKG_VERSION := $(shell python setup.py --version 2>/dev/null)
WHEELSDIR ?= opt/stackstorm/share/wheels
CHANGELOG_COMMENT ?= "automated build, version: $(PKG_VERSION)"
#DEB_EPOCH := $(shell echo $(PKG_VERSION) | grep -q dev || echo '1')
DEB_DISTRO := $(shell [ -z $(DEB_EPOCH) ] && echo unstable || echo stable)

.PHONY: all install install_wheel install_deps deb rpm
all:

install: install_wheel install_deps

install_wheel:
	install -d $(DESTDIR)/$(WHEELSDIR)
	python setup.py bdist_wheel -d $(DESTDIR)/$(WHEELSDIR)

# This step is arch-dependent and must be called only on prepared environment,
# it's run inside stackstorm/buildpack containers.
install_deps:
	pip wheel --wheel-dir=$(DESTDIR)/$(WHEELSDIR) -r requirements.txt
	# Well welcome to enterprise (rhel).
	# Hardcore workaround to make wheel installable on any platform.
	cd $(DESTDIR)/$(WHEELSDIR); \
		ls -1 *-cp27mu-*.whl | while read f; do \
			mv $$f $$(echo $$f | sed "s/cp27mu/none/"); \
		done


deb:
	[ -z "$(DEB_EPOCH)" ] && _epoch="" || _epoch="$(DEB_EPOCH):"; \
		dch -m --force-distribution -v$${_epoch}$(PKG_VERSION)-$(PKG_RELEASE) -D$(DEB_DISTRO) $(CHANGELOG_COMMENT)
	dpkg-buildpackage -b -uc -us -j`_cpunum=$$(nproc); echo "${_cpunum:-1}"`

rpm:
	rpmbuild -bb rpm/st2-auth-ldap.spec
