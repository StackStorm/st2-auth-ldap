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

import os
import time
import uuid

import ldap
import mock
import unittest2

from st2auth_ldap import ldap_backend


LDAP_HOST = '127.0.0.1'
LDAP_MULTIPLE_HOSTS = '127.0.0.1,localhost'
LDAPS_PORT = 636
LDAP_BIND_DN = 'cn=Administrator,cn=users,dc=stackstorm,dc=net'
LDAP_BIND_PASSWORD = uuid.uuid4().hex
LDAP_GROUP_DNS = ['cn=testers,dc=stackstorm,dc=net']
LDAP_CACERT = '../fixtures/certs/cacert.pem'
LDAP_CACERT_REAL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), LDAP_CACERT)
LDAP_BASE_OU = 'dc=stackstorm,dc=net'
LDAP_ID_ATTR = 'uid'
LDAP_USER_UID = 'stanley'
LDAP_USER_UID_2 = 'stanley_2'
LDAP_USER_PASSWD = 'st@nl3y'
LDAP_USER_BAD_PASSWD = 'badbot'

LDAP_USER_INFO_DICT = {
    'accountExpires': ['9223372036854775807'],
    'badPasswordTime': ['0'],
    'badPwdCount': ['0'],
    'cn': ['Tomaz Muraus'],
    'codePage': ['0'],
    'countryCode': ['0'],
    'displayName': ['Tomaz Muraus'],
    'distinguishedName': ['CN=Tomaz Muraus,OU=stormers,DC=stackstorm,DC=net'],
    'givenName': ['Tomaz'],
    'instanceType': ['4'],
    'lastLogoff': ['0'],
    'lastLogon': ['131144315509626450'],
    'lastLogonTimestamp': ['131326807618683640'],
    'logonCount': ['0'],
    'memberOf': ['CN=stormers,OU=groups,DC=stackstorm,DC=net',
                 'CN=testers,OU=groups,DC=stackstorm,DC=net'],
    'name': ['Tomaz Muraus'],
    'objectCategory': ['CN=Person,CN=Schema,CN=Configuration,DC=stackstorm,DC=net'],
    'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
    'objectGUID': ['\x1cR\xca\x12\x8a\xda\x8eL\xabe\xcfp\xda\x17H\xf7'],
    'primaryGroupID': ['513'],
    'pwdLastSet': ['131144314220000000'],
    'sAMAccountName': ['tomaz'],
    'sAMAccountType': ['805306368'],
    'sn': ['Muraus'],
    'uSNChanged': ['9835'],
    'uSNCreated': ['3550'],
    'userAccountControl': ['512'],
    'userPrincipalName': ['tomaz@stackstorm.net'],
    'whenChanged': ['20170227145241.0Z'],
    'whenCreated': ['20160731093701.0Z']
}
LDAP_USER_SEARCH_RESULT = [('cn=Stormin Stanley,cn=users,dc=stackstorm,dc=net',
                           LDAP_USER_INFO_DICT)]
LDAP_GROUP_SEARCH_RESULT = [('cn=testers,dc=stackstorm,dc=net', ()),
                            ('cn=stormers,dc=stackstorm,dc=net', ())]

__all__ = [
    'LDAPBackendTest'
]


class LDAPBackendTest(unittest2.TestCase):

    def test_instantaite_no_group_dns_provided(self):
        # User is member of two of the groups, but none of them are required
        required_group_dns = []
        expected_msg = 'One or more user groups must be specified'
        self.assertRaisesRegexp(ValueError, expected_msg, ldap_backend.LDAPAuthenticationBackend,
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR)

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
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_authenticate_with_multiple_ldap_hosts(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_MULTIPLE_HOSTS,
            id_attr=LDAP_ID_ATTR
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_authenticate_without_password(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        with self.assertRaises(ValueError):
            backend.authenticate(LDAP_USER_UID, '')

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
    def test_authenticate_failure_non_group_member_no_groups(self):
        # User is not member of any of the required group
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='and'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                       [('cn=group1,dc=stackstorm,dc=net', ())]]))
    def test_authenticatefailure_non_group_member_non_required_group(self):
        # User is member of a group which is not required
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='and'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group3,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_and_behavior_failure_non_group_member_of_all_required_groups_1(self):
        # User is member of two of the required groups (1 and 3) but not all three of them
        # (1, 2, 3)
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net',
            'cn=group2,dc=stackstorm,dc=net',
            'cn=group3,dc=stackstorm,dc=net',
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='and'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group3,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_and_behavior_failure_non_group_member_of_all_required_groups_2(self):
        # User is member of two of the groups, but none of them are required
        required_group_dns = [
            'cn=group7,dc=stackstorm,dc=net',
            'cn=group8,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='and'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group2,dc=stackstorm,dc=net', ()),
                                     ('cn=group3,dc=stackstorm,dc=net', ()),
                                     ('cn=group4,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_and_behavior_failure_non_group_member_of_all_required_groups_3(self):
        # User is member of two of the required groups and two non-required, but not
        # all of the required groups
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net',
            'cn=group2,dc=stackstorm,dc=net',
            'cn=group5,dc=stackstorm,dc=net',
            'cn=group6,dc=stackstorm,dc=net',
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='and'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertFalse(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group2,dc=stackstorm,dc=net', ()),
                                     ('cn=group3,dc=stackstorm,dc=net', ()),
                                     ('cn=group4,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_and_is_default_behavior_non_group_member_of_all_required_groups(self):
        # User is member of two of the required groups and two non-required, but not
        # all of the required groups
        # Verify "and" is a default group_dns_check_behavior
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net',
            'cn=group2,dc=stackstorm,dc=net',
            'cn=group5,dc=stackstorm,dc=net',
            'cn=group6,dc=stackstorm,dc=net',
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
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
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_or_behavior_success_member_of_single_group_1(self):
        # User is a memeber of single of possible required groups
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_or_behavior_success_member_of_single_group_2(self):
        # User is a memeber of single of possible required groups
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net',
            'cn=group2,dc=stackstorm,dc=net',
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group3,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_or_behavior_success_member_of_single_group_2b(self):
        # User is a memeber of single of possible required groups
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net',
            'cn=group2,dc=stackstorm,dc=net',
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group4,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_or_behavior_success_member_of_multiple_groups_1(self):
        # User is a memeber of multiple of required groups
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net',
            'cn=group2,dc=stackstorm,dc=net',
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net',
            'cn=group5,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group4,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_or_behavior_success_member_of_multiple_groups_2(self):
        # User is a memeber of multiple of required groups
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group3,dc=stackstorm,dc=net', ()),
                                     ('cn=group6,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_or_behavior_success_member_of_multiple_groups_3(self):
        # User is a memeber of multiple of required groups
        required_group_dns = [
            'cn=group3,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ()),
                                     ('cn=group3,dc=stackstorm,dc=net', ()),
                                     ('cn=group6,dc=stackstorm,dc=net', ())]]))
    def test_authenticate_or_behavior_success_member_of_multiple_groups_3b(self):
        # User is a memeber of multiple of required groups
        required_group_dns = [
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group1,dc=stackstorm,dc=net'
        ]
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or'
        )

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

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

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, []]))
    def test_special_characters_in_username_are_escaped(self):
        # User is not member of any of the required group
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        values = [
            ('stanleyA', 'stanleyA'),
            ('stanley!@?.,&', 'stanley!@?.,&'),
            # Special characters () should be escaped
            ('(stanley)', '\\28stanley\\29'),
            # Special characters () should be escaped
            ('(stanley=)', '\\28stanley=\\29'),
        ]

        for actual_username, expected_username in values:
            backend.authenticate(actual_username, LDAP_USER_BAD_PASSWD)

            call_args_1 = ldap.ldapobject.SimpleLDAPObject.search_s.call_args_list[0][0]
            call_args_2 = ldap.ldapobject.SimpleLDAPObject.search_s.call_args_list[1][0]

            # First search_s call (find user by uid)
            filter_call_value = call_args_1[2]
            self.assertEqual(filter_call_value, 'uid=%s' % (expected_username))

            # Second search_s call (group membership test)
            filter_call_value = call_args_2[2]
            self.assertTrue('(memberUid=%s)' % (expected_username) in filter_call_value)

            ldap.ldapobject.SimpleLDAPObject.search_s = mock.MagicMock(
                side_effect=[LDAP_USER_SEARCH_RESULT, []])

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_get_user(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        user_info = backend.get_user(username=LDAP_USER_UID)
        self.assertEqual(user_info['cn'], ['Tomaz Muraus'])
        self.assertEqual(user_info['displayName'], ['Tomaz Muraus'])
        self.assertEqual(user_info['givenName'], ['Tomaz'])
        self.assertEqual(user_info['primaryGroupID'], ['513'])

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[2 * LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_get_user_multiple_results(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        user_info = backend.get_user(username=LDAP_USER_UID)
        self.assertIsNone(user_info)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT]))
    def test_get_user_groups(self):
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            LDAP_GROUP_DNS,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR
        )

        expected = [
            'cn=testers,dc=stackstorm,dc=net',
            'cn=stormers,dc=stackstorm,dc=net'
        ]

        groups = backend.get_user_groups(username=LDAP_USER_UID)
        self.assertEqual(groups, expected)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ())],
                                    LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ())]
                                    ]))
    def test_authenticate_and_get_user_groups_caching_disabled(self):
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net'
        ]

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or',
            cache_user_groups_response=False
        )

        self.assertEqual(ldap.ldapobject.SimpleLDAPObject.search_s.call_count, 0)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)

        # 1 for user dn search, 1 for groups search
        self.assertEqual(ldap.ldapobject.SimpleLDAPObject.search_s.call_count, 2)

        user_groups = backend.get_user_groups(username=LDAP_USER_UID)
        self.assertEqual(user_groups, ['cn=group1,dc=stackstorm,dc=net'])
        self.assertEqual(ldap.ldapobject.SimpleLDAPObject.search_s.call_count, 4)
        self.assertTrue(backend._user_groups_cache is None)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ())],
                                    LDAP_USER_SEARCH_RESULT,
                                    [('cn=group1,dc=stackstorm,dc=net', ())]
                                    ]))
    def test_authenticate_and_get_user_groups_caching_enabled(self):
        required_group_dns = [
            'cn=group1,dc=stackstorm,dc=net'
        ]

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or',
            cache_user_groups_response=True
        )

        self.assertEqual(ldap.ldapobject.SimpleLDAPObject.search_s.call_count, 0)

        authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
        self.assertTrue(authenticated)
        self.assertEqual(ldap.ldapobject.SimpleLDAPObject.search_s.call_count, 2)

        user_groups = backend.get_user_groups(username=LDAP_USER_UID)
        self.assertEqual(user_groups, ['cn=group1,dc=stackstorm,dc=net'])
        self.assertEqual(ldap.ldapobject.SimpleLDAPObject.search_s.call_count, 2)
        self.assertTrue(LDAP_USER_UID in backend._user_groups_cache)

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT]))
    def test_get_user_specifying_account_pattern(self):
        expected_username = 'unique_username_1'
        required_group_dns = [
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net'
        ]
        scope = 'subtree'
        scope_number = ldap_backend.SEARCH_SCOPES[scope]

        account_pattern = '''
        (&
          (objectClass=person)
          (|
            (accountName={username})
            (mail={username})
          )
        )
        '''.replace('\n', '').replace(' ', '')
        expected_account_pattern = account_pattern.format(username=expected_username)

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            scope=scope,
            account_pattern=account_pattern,
        )
        connection = mock.MagicMock()
        backend._init_connection = mock.MagicMock(return_value=connection)
        backend.get_user(expected_username)

        connection.search_s.assert_called_once_with(LDAP_BASE_OU, scope_number,
                                                    expected_account_pattern, [])

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group3,dc=stackstorm,dc=net', ())],
                                    LDAP_USER_SEARCH_RESULT,
                                    [('cn=group4,dc=stackstorm,dc=net', ())]
                                    ]))
    def test_get_user_groups_specifying_group_pattern(self):
        expected_user_dn = 'unique_userdn_1'
        expected_username = 'unique_username_2'
        required_group_dns = [
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net'
        ]
        scope = 'subtree'
        scope_number = ldap_backend.SEARCH_SCOPES[scope]

        group_pattern = '''
        (|
          (&
            (objectClass=group)
            (|
              (memberUserdn={user_dn})
              (uniqueMemberUserdn={user_dn})
              (memberUid={username})
              (uniqueMemberUid={username})
            )
          )
        )
        '''.replace('\n', '').replace(' ', '')
        expected_group_pattern = group_pattern.format(
            user_dn=expected_user_dn,
            username=expected_username,
        )

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            scope=scope,
            group_pattern=group_pattern,
            cache_user_groups_response=False,
        )
        connection = mock.MagicMock()
        backend._init_connection = mock.MagicMock(return_value=connection)
        backend._get_user_dn = mock.MagicMock(return_value=expected_user_dn)

        backend.get_user_groups(expected_username)
        connection.search_s.assert_called_with(LDAP_BASE_OU, scope_number,
                                               expected_group_pattern, [])

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group3,dc=stackstorm,dc=net', ())],
                                    LDAP_USER_SEARCH_RESULT,
                                    [('cn=group4,dc=stackstorm,dc=net', ())]
                                    ]))
    def test_get_groups_caching_no_cross_username_cache_polution(self):
        required_group_dns = [
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net'
        ]
        # Test which verifies that cache items are correctly scoped per username
        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or',
            cache_user_groups_response=True
        )
        user_groups = backend.get_user_groups(username=LDAP_USER_UID)
        self.assertEqual(user_groups, ['cn=group3,dc=stackstorm,dc=net'])
        self.assertEqual(backend._user_groups_cache[LDAP_USER_UID],
                         ['cn=group3,dc=stackstorm,dc=net'])

        user_groups = backend.get_user_groups(username=LDAP_USER_UID_2)
        self.assertEqual(user_groups, ['cn=group4,dc=stackstorm,dc=net'])
        self.assertEqual(backend._user_groups_cache[LDAP_USER_UID_2],
                         ['cn=group4,dc=stackstorm,dc=net'])

    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'simple_bind_s',
        mock.MagicMock(return_value=None))
    @mock.patch.object(
        ldap.ldapobject.SimpleLDAPObject, 'search_s',
        mock.MagicMock(side_effect=[LDAP_USER_SEARCH_RESULT,
                                    [('cn=group3,dc=stackstorm,dc=net', ())],
                                    LDAP_USER_SEARCH_RESULT,
                                    [('cn=group4,dc=stackstorm,dc=net', ())]
                                    ]))
    def test_get_groups_caching_cache_ttl(self):
        required_group_dns = [
            'cn=group3,dc=stackstorm,dc=net',
            'cn=group4,dc=stackstorm,dc=net'
        ]

        backend = ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
            group_dns_check='or',
            cache_user_groups_response=True,
            cache_user_groups_cache_ttl=1
        )
        user_groups = backend.get_user_groups(username=LDAP_USER_UID)
        self.assertEqual(user_groups, ['cn=group3,dc=stackstorm,dc=net'])
        self.assertTrue(LDAP_USER_UID in backend._user_groups_cache)
        self.assertEqual(backend._user_groups_cache[LDAP_USER_UID],
                         ['cn=group3,dc=stackstorm,dc=net'])

        # After 1 second, cache entry should expire and it should result in another search_s call
        # which returns group4
        time.sleep(1.5)

        user_groups = backend.get_user_groups(username=LDAP_USER_UID)
        self.assertEqual(user_groups, ['cn=group4,dc=stackstorm,dc=net'])
        self.assertTrue(LDAP_USER_UID in backend._user_groups_cache)
        self.assertEqual(backend._user_groups_cache[LDAP_USER_UID],
                         ['cn=group4,dc=stackstorm,dc=net'])

        # Cache should now be empty
        time.sleep(1.5)
        self.assertFalse(LDAP_USER_UID in backend._user_groups_cache)
