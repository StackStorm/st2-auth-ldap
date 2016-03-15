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

LDAP_USER_SEARCH_RESULT = [('cn=Jon Snow,cn=users,dc=stackstorm,dc=net', [])]
LDAP_GROUP_SEARCH_RESULT = [('cn=testers,dc=stackstorm,dc=net', [])]


class OpenLDAPAuthenticationTest(unittest2.TestCase):

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_authenticate(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)

        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(side_effect=Exception()))
    def test_authenticate_failure_bad_bind_cred(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)

        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(side_effect=[None, Exception()]))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_authenticate_failure_bad_user_password(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)

        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, []]))
    def test_authenticate_failure_non_group_member(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)

        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_ssl_authenticate(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            port=LDAPS_PORT,
            use_ssl=True,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)

        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(side_effect=[None, Exception()]))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_ssl_authenticate_failure(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            port=LDAPS_PORT,
            use_ssl=True,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)

        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_ssl_authenticate_validate_cert(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            port=LDAPS_PORT,
            use_ssl=True,
            cacert=LDAP_CACERT_REAL_PATH,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)

        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'start_tls_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_tls_authenticate(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            use_tls=True,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)

        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'start_tls_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(side_effect=[None, Exception()]))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_tls_authenticate_failure(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            use_tls=True,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)

        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'start_tls_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_tls_authenticate_validate_cert(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            use_tls=True,
            cacert=LDAP_CACERT_REAL_PATH,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)

        self.assertTrue(authenticated)
