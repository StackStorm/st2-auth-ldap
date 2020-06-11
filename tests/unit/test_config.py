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

import ldap
import os
import mock
import unittest2
import uuid

from st2auth_enterprise_ldap_backend import ldap_backend


LDAP_HOST = '127.0.0.1'
LDAPS_PORT = 636
LDAP_BIND_DN = 'cn=Administrator,cn=users,dc=stackstorm,dc=net'
LDAP_BIND_PASSWORD = uuid.uuid4().hex
LDAP_GROUP_DNS = ['cn=testers,dc=stackstorm,dc=net']
LDAP_CACERT = '../fixtures/certs/cacert.pem'
LDAP_CACERT_REAL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), LDAP_CACERT)
LDAP_BASE_OU = 'dc=stackstorm,dc=net'
LDAP_ID_ATTR = 'uid'
LDAP_USER_UID = 'jon'
LDAP_USER_PASSWD = 'snow123'
LDAP_USER_BAD_PASSWD = 'snow1234'


class LDAPBackendConfigurationTest(unittest2.TestCase):

    def test_null_bind_dn(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            None,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST
        )

    def test_null_bind_password(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            None,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST
        )

    def test_null_base_ou(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            None,
            LDAP_GROUP_DNS,
            LDAP_HOST
        )

    def test_null_group_dns(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            None,
            LDAP_HOST
        )

    def test_null_host(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            None
        )

    def test_null_port(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            port=None
        )

        self.assertEqual(389, backend._port)

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            port=None,
            use_ssl=True
        )

        self.assertEqual(LDAPS_PORT, backend._port)

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            port=9090,
            use_ssl=True
        )

        self.assertEqual(9090, backend._port)

    def test_scope(self):
        for scope in ['base', 'onelevel', 'subtree']:
            backend = ldap_backend.LDAPAuthenticationBackend(
                LDAP_BIND_DN,
                LDAP_BIND_PASSWORD,
                LDAP_BASE_OU,
                LDAP_GROUP_DNS,
                LDAP_HOST,
                scope=scope
            )

            self.assertEqual(ldap_backend.SEARCH_SCOPES[scope], backend._scope)

    def test_bad_scope(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            scope='foo'
        )

    def test_null_id_attr(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=None
        )

        self.assertEqual('uid', backend._id_attr)

    def test_both_ssl_tls_true(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            use_ssl=True,
            use_tls=True
        )

    def test_bad_cacert_file(self):
        self.assertRaises(
            ValueError,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            cacert='/tmp/foobar'
        )

    @mock.patch.object(
        ldap, 'initialize',
        mock.MagicMock(side_effect=ldap.LDAPError()))
    def test_connection_error(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)

        self.assertFalse(authenticated)

    def test_chase_referrals(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            chase_referrals=False
        )

        conn = backend._init_connection()
        self.assertFalse(conn.get_option(ldap.OPT_REFERRALS))

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            chase_referrals=True
        )

        conn = backend._init_connection()
        self.assertTrue(conn.get_option(ldap.OPT_REFERRALS))

    def test_client_options(self):
        client_options = {
            ldap.OPT_RESTART: 0,
            ldap.OPT_SIZELIMIT: 2014,
            ldap.OPT_DIAGNOSTIC_MESSAGE: 'test',
            # Not using a constant, 20482 is OPT_TIMEOUT
            '20482': 9
        }

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            client_options=client_options
        )

        conn = backend._init_connection()
        for option_name, option_value in client_options.items():
            self.assertEqual(conn.get_option(int(option_name)), option_value)

    def test_invalid_group_dns_check_option(self):
        expected_msg = ('Invalid value "invalid" for group_dns_check option. Valid '
                        'values are: and, or.')
        self.assertRaisesRegexp(
            ValueError,
            expected_msg,
            ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            group_dns_check='invalid'
        )

    def test_and_is_default_group_dns_check_value(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )
        self.assertEqual(backend._group_dns_check, 'and')
