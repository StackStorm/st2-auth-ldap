# Licensed to the StackStorm, Inc ('StackStorm') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ldap
import mock
import unittest2

from st2auth_enterprise_ldap_backend import ldap_backend


LDAP_HOST = 'ldap202.uswest2.stackstorm.net'
LDAPS_PORT = 636
LDAP_USERS_OU = 'ou=users,dc=staging,dc=stackstorm,dc=net'
LDAP_CACERT = '/home/wcchan/Downloads/cacert.pem'
LDAP_USER_UID = 'jon'
LDAP_USER_PASSWD = 'snow123'
LDAP_USER_BAD_PASSWD = 'snow1234'


class LDAPBackendAuthenticationTest(unittest2.TestCase):

    def test_null_host(self):
        self.assertRaises(ValueError, ldap_backend.LDAPAuthenticationBackend,
                          users_ou=LDAP_USERS_OU, host=None)

    def test_null_users_ou(self):
        self.assertRaises(ValueError, ldap_backend.LDAPAuthenticationBackend,
                          users_ou=None, host=LDAP_HOST)

    def test_null_port(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST, port=None)

        self.assertEqual(389, backend._port)

        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST, port=None, use_ssl=True)

        self.assertEqual(636, backend._port)

        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST, port=9090, use_ssl=True)

        self.assertEqual(9090, backend._port)

    def test_bad_scope(self):
        self.assertRaises(ValueError, ldap_backend.LDAPAuthenticationBackend,
                          users_ou=LDAP_USERS_OU, host=LDAP_HOST, scope=-1)

        self.assertRaises(ValueError, ldap_backend.LDAPAuthenticationBackend,
                          users_ou=LDAP_USERS_OU, host=LDAP_HOST, scope=3)

    def test_null_id_attr(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST, id_attr=None)

        self.assertEqual('uid', backend._id_attr)

    def test_both_ssl_tls_true(self):
        self.assertRaises(ValueError, ldap_backend.LDAPAuthenticationBackend,
                          users_ou=LDAP_USERS_OU, host=LDAP_HOST,
                          use_ssl=True, use_tls=True)

    def test_bad_cacert_file(self):
        self.assertRaises(ValueError, ldap_backend.LDAPAuthenticationBackend,
                          users_ou=LDAP_USERS_OU, host=LDAP_HOST,
                          cacert='/tmp/foobar')

    @mock.patch.object(
        ldap, 'initialize',
        mock.MagicMock(side_effect=ldap.LDAPError()))
    def test_connection_error(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    def test_authenticate(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(side_effect=Exception()))
    def test_authenticate_failure(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    def test_ssl_authenticate(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST,
            port=LDAPS_PORT, use_ssl=True)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(side_effect=Exception()))
    def test_ssl_authenticate_failure(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST,
            port=LDAPS_PORT, use_ssl=True)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    def test_ssl_authenticate_validate_cert(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST,
            port=LDAPS_PORT, use_ssl=True, cacert=LDAP_CACERT)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    def test_tls_authenticate(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST, use_tls=True)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(side_effect=Exception()))
    def test_tls_authenticate_failure(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST, use_tls=True)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    def test_tls_authenticate_validate_cert(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            users_ou=LDAP_USERS_OU, host=LDAP_HOST,
            use_tls=True, cacert=LDAP_CACERT)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
        self.assertTrue(authenticated)
