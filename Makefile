# Copyright (C) 2020 Extreme Networks, Inc - All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SHELL := /bin/bash
PKG_NAME := st2-auth-ldap
PKG_RELEASE ?= 1
WHEELSDIR ?= opt/stackstorm/share/wheels
VIRTUALENV_DIR ?= virtualenv

ST2_REPO_PATH ?= /tmp/st2
ST2_REPO_BRANCH ?= master

DEBIAN := 0
REDHAT := 0

ifneq (,$(wildcard /etc/debian_version))
    DEBIAN := 1
else
    REDHAT := 1
endif

DEB_DISTRO := $(shell lsb_release -cs)
REDHAT_DISTRO := $(shell rpm --eval '%{rhel}')

ifeq ($(DEB_DISTRO),)
    DEB_DISTRO := "unstable"
endif

ifeq ($(REDHAT_DISTRO),)
    REDHAT_DISTRO := 0
endif

ifeq ($(REDHAT_DISTRO),$(shell echo "%{rhel}"))
    REDHAT_DISTRO := 0
endif

ifeq ($(DEB_DISTRO),bionic)
	PYTHON_BINARY := /usr/bin/python3
	PIP_BINARY := /usr/local/bin/pip3
else ifeq ($(shell test $(REDHAT_DISTRO) -ge 8; echo $$?), 0)
	PYTHON_BINARY := $(shell which python3)
	PIP_BINARY := $(shell which pip3)
else
	PYTHON_BINARY := python
	PIP_BINARY := pip
endif

# NOTE: We remove trailing "0" which is added at the end by newer versions of pip
# For example: 3.0.dev0 -> 3.0.dev
PKG_VERSION := $(shell $(PYTHON_BINARY) setup.py --version 2> /dev/null | sed 's/\.dev[0-9]$$/dev/')
CHANGELOG_COMMENT ?= "automated build, version: $(PKG_VERSION)"

REQUIREMENTS := test-requirements.txt requirements.txt
PIP_OPTIONS := $(ST2_PIP_OPTIONS)

# nasty hack to get a space into a variable
space_char :=
space_char +=
comma := ,
COMPONENTS = $(wildcard $(ST2_REPO_PATH)/st2*)
COMPONENT_PYTHONPATH = $(subst $(space_char),:,$(realpath $(COMPONENTS)))

.PHONY: play
play:
	@echo "DEBIAN=$(DEBIAN)"
	@echo "DEB_DISTRO=$(DEB_DISTRO)"
	@echo "REDHAT=$(REDHAT)"
	@echo "REDHAT_DISTRO=$(REDHAT_DISTRO)"
	@echo "PYTHON_BINARY=$(PYTHON_BINARY)"
	@echo "PIP_BINARY=$(PIP_BINARY)"
	@echo "PKG_VERSION=$(PKG_VERSION)"
	@echo "PKG_RELEASE=$(PKG_RELEASE)"
	@echo
	@echo "`cat /etc/os-release`"
	@echo

.PHONY: requirements
requirements: virtualenv
	@echo
	@echo "==================== requirements ===================="
	@echo

	# Install requirements
	for req in $(REQUIREMENTS); do \
			echo "Installing $$req..." ; \
			$(VIRTUALENV_DIR)/bin/pip install $(PIP_OPTIONS) -r $$req; \
	done

	# Install st2 requirements
	$(VIRTUALENV_DIR)/bin/pip install -r $(ST2_REPO_PATH)/requirements.txt; \

.PHONY: virtualenv
virtualenv: $(VIRTUALENV_DIR)/bin/activate .clone_st2_repo
$(VIRTUALENV_DIR)/bin/activate:
	@echo
	@echo "==================== virtualenv ===================="
	@echo
	test -d $(VIRTUALENV_DIR) || virtualenv --no-site-packages $(VIRTUALENV_DIR)

	# Setup PYTHONPATH in bash activate script...
	echo '' >> $(VIRTUALENV_DIR)/bin/activate
	echo '_OLD_PYTHONPATH=$$PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate
	echo 'PYTHONPATH=$$_OLD_PYTHONPATH:$(COMPONENT_PYTHONPATH)' >> $(VIRTUALENV_DIR)/bin/activate
	echo 'export PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate
	touch $(VIRTUALENV_DIR)/bin/activate

	# Setup PYTHONPATH in fish activate script...
	echo '' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo 'set -gx _OLD_PYTHONPATH $$PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo 'set -gx PYTHONPATH $$_OLD_PYTHONPATH $(COMPONENT_PYTHONPATH)' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo 'functions -c deactivate old_deactivate' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo 'function deactivate' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo '  if test -n $$_OLD_PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo '    set -gx PYTHONPATH $$_OLD_PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo '    set -e _OLD_PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo '  end' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo '  old_deactivate' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo '  functions -e old_deactivate' >> $(VIRTUALENV_DIR)/bin/activate.fish
	echo 'end' >> $(VIRTUALENV_DIR)/bin/activate.fish
	touch $(VIRTUALENV_DIR)/bin/activate.fish

.PHONY: lint
lint: requirements .clone_st2_repo .lint

.PHONY: .lint
.lint:
	. $(VIRTUALENV_DIR)/bin/activate; flake8 --config ./lint-configs/python/.flake8 st2auth_ldap/
	. $(VIRTUALENV_DIR)/bin/activate; pylint -E --rcfile=./lint-configs/python/.pylintrc st2auth_ldap/

.PHONY: unit-tests
unit-tests: requirements .clone_st2_repo .unit-tests

.PHONY: .unit-tests
.unit-tests:
	@echo
	@echo "==================== tests ===================="
	@echo
	echo "==========================================================="; \
	echo "Running unit tests"; \
	echo "==========================================================="; \
	. $(VIRTUALENV_DIR)/bin/activate; nosetests $(NOSE_OPTS) -s -v tests/unit || exit 1; \

.PHONY: .clone_st2_repo
.clone_st2_repo:
	@echo
	@echo "==================== cloning st2 repo ===================="
	@echo
	@rm -rf /tmp/st2
	@git clone https://github.com/StackStorm/st2.git --depth 1 --single-branch --branch $(ST2_REPO_BRANCH) /tmp/st2

.PHONY: all install install_wheel install_deps deb rpm
all:

install: install_wheel install_deps

install_wheel:
	install -d $(DESTDIR)/$(WHEELSDIR)
	$(PYTHON_BINARY) setup.py bdist_wheel -d $(DESTDIR)/$(WHEELSDIR)

# This step is arch-dependent and must be called only on prepared environment,
# it's run inside stackstorm/buildpack containers.
install_deps:
	$(PIP_BINARY) wheel --wheel-dir=$(DESTDIR)/$(WHEELSDIR) -r requirements.txt
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
