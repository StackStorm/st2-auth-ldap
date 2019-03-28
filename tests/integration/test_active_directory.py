# Copyright (c) Extreme Networks, Inc - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential

import os
import unittest2

from st2auth_enterprise_ldap_backend import ldap_backend


class ActiveDirectoryAuthenticationTest(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        super(ActiveDirectoryAuthenticationTest, cls).setUpClass()
        cls.ldap_host = os.environ.get('ST2_LDAP_HOST', '127.0.0.1')
        cls.ldap_bind_dn = os.environ.get('ST2_LDAP_BIND_DN', 'cn=admin,dc=stackstorm,dc=net')
        cls.ldap_bind_pass = os.environ.get('ST2_LDAP_BIND_PASS', 'foobar')
        cls.ldap_base_ou = os.environ.get('ST2_LDAP_BASE_OU', 'dc=stackstorm,dc=net')
        cls.ldap_id_attr = os.environ.get('ST2_LDAP_ID_ATTR', 'sAMAccountName')

    def test_authenticate(self):
        ldap_group_dns = ['cn=testers,ou=groups,dc=stackstorm,dc=net']
        ldap_user_uid = 'stanley'
        ldap_user_passwd = 'stanl3y!'

        backend = ldap_backend.LDAPAuthenticationBackend(
            self.ldap_bind_dn,
            self.ldap_bind_pass,
            self.ldap_base_ou,
            ldap_group_dns,
            self.ldap_host,
            id_attr=self.ldap_id_attr
        )

        authenticated = backend.authenticate(ldap_user_uid, ldap_user_passwd)

        self.assertTrue(authenticated)
