# Copyright (C) 2020 Extreme Networks, Inc - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential.
# See the LICENSE file included with this work for details.

import os

from setuptools import setup, find_packages
from dist_utils import check_pip_version
from dist_utils import fetch_requirements
from dist_utils import parse_version_string
# Monkey patch to avoid version normalization like '2.9dev' -> '2.9.dev0', (https://github.com/pypa/setuptools/issues/308)
# NOTE: This doesn't work under Bionic
# from setuptools.extern.packaging import version
# version.Version = version.LegacyVersion

check_pip_version()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS_FILE = os.path.join(BASE_DIR, 'requirements.txt')
INIT_FILE = os.path.join(BASE_DIR, 'st2auth_enterprise_ldap_backend', '__init__.py')

version = parse_version_string(INIT_FILE)
install_reqs, dep_links = fetch_requirements(REQUIREMENTS_FILE)

setup(
    name='st2-enterprise-auth-backend-ldap',
    version=version,
    description='StackStorm enterprise authentication backend for LDAP.',
    author='StackStorm, Inc.',
    author_email='info@stackstorm.com',
    url='https://github.com/extremenetworks/st2-enterprise-auth-backend-ldap',
    license='Proprietary License',
    download_url='https://github.com/extremenetworks/st2-enterprise-auth-backend-ldap/tarball/master',
    classifiers=[
        'License :: Other/Proprietary License'
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Environment :: Console',
    ],
    platforms=['Any'],
    scripts=[],
    provides=['st2auth_enterprise_ldap_backend'],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_reqs,
    dependency_links=dep_links,
    test_suite='tests',
    entry_points={
        'st2auth.backends.backend': [
            'ldap = st2auth_enterprise_ldap_backend.ldap_backend:LDAPAuthenticationBackend',
        ],
    },
    zip_safe=False
)
