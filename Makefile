# Copyright 2020 The StackStorm Authors.
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
VIRTUALENV_DIR ?= virtualenv

ST2_REPO_PATH ?= /tmp/st2
ST2_REPO_BRANCH ?= master

PIP_OPTIONS := $(ST2_PIP_OPTIONS)

# nasty hack to get a space into a variable
empty:=
space_char:= $(empty) $(empty)
comma := ,
COMPONENTS = $(wildcard $(ST2_REPO_PATH)/st2*)
COMPONENTS_RUNNERS := $(wildcard $(ST2_REPO_PATH)/contrib/runners/*)
COMPONENTS_WITH_RUNNERS := $(COMPONENTS) $(COMPONENTS_RUNNERS)
COMPONENT_PYTHONPATH = $(subst $(space_char),:,$(realpath $(COMPONENTS_WITH_RUNNERS))):$(ST2_REPO_PATH):$(CURRENT_DIR)
COMPONENTS_TEST := $(foreach component,$(filter-out $(COMPONENT_SPECIFIC_TESTS),$(COMPONENTS_WITH_RUNNERS)),$(component))
COMPONENTS_TEST_COMMA := $(subst $(slash),$(dot),$(subst $(space_char),$(comma),$(COMPONENTS_TEST)))
COMPONENTS_TEST_MODULES := $(subst $(slash),$(dot),$(COMPONENTS_TEST_DIRS))
COMPONENTS_TEST_MODULES_COMMA := $(subst $(space_char),$(comma),$(COMPONENTS_TEST_MODULES))

ifndef PYLINT_CONCURRENCY
	PYLINT_CONCURRENCY := 1
endif

.PHONY: play
play:
	@echo
	@echo "`cat /etc/os-release`"
	@echo

.PHONY: requirements
requirements: .clone_st2_repo virtualenv
	@echo
	@echo "==================== requirements ===================="
	@echo
	$(eval PIP_VERSION := $(shell grep 'PIP_VERSION ?= ' /tmp/st2/Makefile | awk '{ print $$3}'))
	$(VIRTUALENV_DIR)/bin/pip install --upgrade "pip==$(PIP_VERSION)"
	$(VIRTUALENV_DIR)/bin/pip install --cache-dir $(HOME)/.pip-cache $(PIP_OPTIONS) -r $(ST2_REPO_PATH)/requirements.txt
	$(VIRTUALENV_DIR)/bin/pip install --cache-dir $(HOME)/.pip-cache $(PIP_OPTIONS) -r $(ST2_REPO_PATH)/test-requirements.txt
	$(VIRTUALENV_DIR)/bin/pip install --cache-dir $(HOME)/.pip-cache $(PIP_OPTIONS) -r requirements.txt
	$(VIRTUALENV_DIR)/bin/pip install --cache-dir $(HOME)/.pip-cache $(PIP_OPTIONS) -r test-requirements.txt

	@echo ""
	@echo "================== register st2auth ======================"
	@echo ""
	# Install st2auth
	(. $(VIRTUALENV_DIR)/bin/activate; cd $(ST2_REPO_PATH)/st2auth; python3 setup.py develop --no-deps)
	@echo ""
	@echo "================== register ldap ======================"
	@echo ""
	(. $(VIRTUALENV_DIR)/bin/activate; python3 setup.py develop --no-deps)

.PHONY: requirements-ci

.PHONY: virtualenv
virtualenv: $(VIRTUALENV_DIR)/bin/activate .clone_st2_repo
$(VIRTUALENV_DIR)/bin/activate:
	@echo
	@echo "==================== virtualenv ===================="
	@echo
	test -d $(VIRTUALENV_DIR) || virtualenv $(VIRTUALENV_DIR) -p python3

	# Setup PYTHONPATH in bash activate script...
	# Delete existing entries (if any)
ifeq ($(OS),Darwin)
	echo 'Setting up virtualenv on $(OS)...'
	sed -i '' '/_OLD_PYTHONPATHp/d' $(VIRTUALENV_DIR)/bin/activate
	sed -i '' '/PYTHONPATH=/d' $(VIRTUALENV_DIR)/bin/activate
	sed -i '' '/export PYTHONPATH/d' $(VIRTUALENV_DIR)/bin/activate
else
	echo 'Setting up virtualenv on $(OS)...'
	sed -i '/_OLD_PYTHONPATHp/d' $(VIRTUALENV_DIR)/bin/activate
	sed -i '/PYTHONPATH=/d' $(VIRTUALENV_DIR)/bin/activate
	sed -i '/export PYTHONPATH/d' $(VIRTUALENV_DIR)/bin/activate
endif

	echo '_OLD_PYTHONPATH=$$PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate
	echo 'PYTHONPATH=$(COMPONENT_PYTHONPATH)' >> $(VIRTUALENV_DIR)/bin/activate
	echo 'export PYTHONPATH' >> $(VIRTUALENV_DIR)/bin/activate
	touch $(VIRTUALENV_DIR)/bin/activate

.PHONY: all
all: requirements lint unit-tests

.PHONY: lint
lint: requirements flake8 pylint

.PHONY: .lint
.lint: requirements .flake8 .pylint

.PHONY: flake8
flake8: requirements .clone_st2_repo .flake8

.PHONY: pylint
pylint: requirements .clone_st2_repo .pylint

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
	. $(VIRTUALENV_DIR)/bin/activate; pytest tests/unit || exit 1; \

.PHONY: .clone_st2_repo
.clone_st2_repo:
	@echo
	@echo "==================== cloning st2 repo ===================="
	@echo
	@rm -rf /tmp/st2
	@git clone https://github.com/StackStorm/st2.git --depth 1 --single-branch --branch $(ST2_REPO_BRANCH) /tmp/st2

.PHONY: .flake8
.flake8:
	@echo
	@echo "==================== flake8 ===================="
	@echo
	. $(VIRTUALENV_DIR)/bin/activate; flake8 --config=lint-configs/python/.flake8 st2auth_ldap/ tests/

.PHONY: .pylint
.pylint:
	@echo
	@echo "==================== pylint ===================="
	@echo
	. $(VIRTUALENV_DIR)/bin/activate; pylint -j $(PYLINT_CONCURRENCY) -E --rcfile=./lint-configs/python/.pylintrc st2auth_ldap/
