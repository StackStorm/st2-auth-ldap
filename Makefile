SHELL := /bin/bash
PKG_NAME := st2-auth-ldap
PKG_RELEASE ?= 1
WHEELSDIR ?= opt/stackstorm/share/wheels
CHANGELOG_COMMENT ?= "automated build, version: $(PKG_VERSION)"
#DEB_EPOCH := $(shell echo $(PKG_VERSION) | grep -q dev || echo '1')
DEB_DISTRO := $(shell [ -z $(DEB_EPOCH) ] && echo unstable || echo stable)
VIRTUALENV_DIR ?= virtualenv

ST2_REPO_PATH ?= /tmp/st2
ST2_REPO_BRANCH ?= master

ifneq (,$(wildcard /etc/debian_version))
	DEBIAN := 1
	DEB_DISTRO_NAME := $(shell lsb_release -cs)
else
	REDHAT := 1
	DEB_DISTRO_NAME := unstable
endif

ifeq ($(DEB_DISTRO_NAME),bionic)
	PYTHON_BINARY := /usr/bin/python3
	PIP_BINARY := /usr/bin/pip3
else
	PYTHON_BINARY := python
	PIP_BINARY := pip
endif

PKG_VERSION := $(shell $(PYTHON_BINARY) setup.py --version 2>/dev/null)

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
	@echo "REDHAT=$(REDHAT)"
	@echo "DEB_DISTRO=$(DEB_DISTRO)"
	@echo "DEB_DISTRO_NAME=$(DEB_DISTRO_NAME)"
	@echo "PYTHON_BINARY=$(PYTHON_BINARY)"
	@echo "PIP_BINARY=$(PIP_BINARY)"
	@echo "PKG_VERSION=$(PKG_VERSION)"

.PHONY: requirements
requirements: virtualenv
	@echo
	@echo "==================== requirements ===================="
	@echo

	# Make sure we use latest version of pip which works
	$(VIRTUALENV_DIR)/bin/pip install --upgrade "pip>=9.0,<9.1"

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
	. $(VIRTUALENV_DIR)/bin/activate; flake8 --config ./lint-configs/python/.flake8 st2auth_enterprise_ldap_backend/
	. $(VIRTUALENV_DIR)/bin/activate; pylint -E --rcfile=./lint-configs/python/.pylintrc st2auth_enterprise_ldap_backend/

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
