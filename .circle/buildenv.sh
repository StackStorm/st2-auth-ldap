#!/bin/bash
set -e

# Write export lines into ~/.buildenv and also source it in ~/.circlerc
write_env() {
  for e in $*; do
    eval "value=\$$e"
    [ -z "$value" ] || echo "export $e=$value" >> ~/.buildenv
  done
  echo ". ~/.buildenv" >> ~/.circlerc
}

fetch_version() {
  if [ -f ../st2auth_enterprise_ldap_backend/__init__.py ]; then
    # Get st2 version based on hardcoded string in st2common
    # build takes place in `st2` repo
    python -c 'execfile("../st2auth_enterprise_ldap_backend/__init__.py"); print __version__'
  fi
}

PKG_VERSION=$(fetch_version)

# for Bintray
#ST2PKG_RELEASE=$(.circle/bintray.sh next-revision ${DISTRO}_staging ${ST2PKG_VERSION} st2)
# for PackageCloud
if [ -z "$CIRCLE_PR_REPONAME" ]; then
  PKG_RELEASE=$(.circle/packagecloud.sh next-revision ${DISTRO} ${PKG_VERSION} st2-enterprise-auth-backend-ldap)
else
  # is fork
  PKG_RELEASE=1
fi

write_env PKG_VERSION PKG_RELEASE
