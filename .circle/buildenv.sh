#!/bin/bash
set -e

circle_dir="$(dirname "$0")"

distros=($DISTROS)
DISTRO=${distros[$CIRCLE_NODE_INDEX]}

# Write export lines into ~/.buildenv and also source it in ~/.circlerc
write_env() {
  for e in $*; do
    eval "value=\$$e"
    [ -z "$value" ] || echo "export $e=$value" >> ~/.buildenv
  done
  echo ". ~/.buildenv" >> ~/.circlerc
}

fetch_version() {
  cat
  if [ -f ${circle_dir}/../st2auth_enterprise_ldap_backend/__init__.py ]; then
    # Get st2 version based on hardcoded string in st2common
    # build takes place in `st2-enterprise-auth-backend-ldap` repo
    python -c "execfile(\"${circle_dir}/skip_import.py\"); execfile(\"${circle_dir}/../st2auth_enterprise_ldap_backend/__init__.py\"); print __version__"
  fi
}

PKG_VERSION=$(fetch_version)

# for PackageCloud
if [ -z "$CIRCLE_PR_REPONAME" ]; then
  PKG_RELEASE=$(${circle_dir}/packagecloud.sh next-revision "${DISTRO}" "${PKG_VERSION}" st2-enterprise-auth-backend-ldap)
else
  # is fork
  PKG_RELEASE=1
fi

write_env PKG_VERSION PKG_RELEASE
