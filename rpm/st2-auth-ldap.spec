%define pyexe %(which python)

%if 0%{?rhel} >= 8
%define pyexe %(which python3)
%endif

%define pkg_version %(%{pyexe} setup.py --version 2>/dev/null)
%define version %(echo "${PKG_VERSION:-%{pkg_version}}")
%define release %(echo "${PKG_RELEASE:-1}")
%define st2dir /opt/stackstorm
%define st2wheels %{st2dir}/share/wheels
%define pip %{st2dir}/st2/bin/pip

Name:           st2-auth-ldap
Version:        %{version}
%if 0%{?epoch}
Epoch: %{epoch}
%endif
Release:        %{release}
License:        Apache 2.0
Summary:        LDAP authentication plugin for StackStorm
URL:            https://stackstorm.com
Source0:        st2-enterprise-auth-backend-ldap

Requires: st2 openldap

%define _builddir %(pwd)
%define _rpmdir %(pwd)/build

%description
  LDAP Authentication Backend for StackStorm

%prep
  rm -rf %{buildroot}
  mkdir -p %{buildroot}

%build
  make

%install
  %make_install

%clean
  rm -rf %{buildroot}

%post
  %{pip} install --find-links %{st2wheels} --no-index --quiet --upgrade st2-enterprise-auth-backend-ldap

%postun
  if [ $1 -eq 0 ]; then
    %{pip} uninstall -y --quiet st2-enterprise-auth-backend-ldap 1>/dev/null || :
  fi

%files
  %doc rpm/LICENSE
  %{st2wheels}/*
