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
import pytest
from pytest_mock import MockerFixture, MockType

from st2auth_ldap import ldap_backend


LDAP_HOST = "127.0.0.1"
LDAP_MULTIPLE_HOSTS = "127.0.0.1,localhost"
LDAPS_PORT = 636
LDAP_BIND_DN = "cn=Administrator,cn=users,dc=stackstorm,dc=net"
LDAP_BIND_PASSWORD = uuid.uuid4().hex
LDAP_GROUP_DNS = ["cn=testers,dc=stackstorm,dc=net"]
LDAP_CACERT = "../fixtures/certs/cacert.pem"
LDAP_CACERT_REAL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), LDAP_CACERT
)
LDAP_BASE_OU = "dc=stackstorm,dc=net"
LDAP_ID_ATTR = "uid"
LDAP_USER_UID = "stanley"
LDAP_USER_UID_2 = "stanley_2"
LDAP_USER_PASSWD = "st@nl3y"
LDAP_USER_BAD_PASSWD = "badbot"

LDAP_USER_INFO_DICT = {
    "accountExpires": ["9223372036854775807"],
    "badPasswordTime": ["0"],
    "badPwdCount": ["0"],
    "cn": ["Tomaz Muraus"],
    "codePage": ["0"],
    "countryCode": ["0"],
    "displayName": ["Tomaz Muraus"],
    "distinguishedName": ["CN=Tomaz Muraus,OU=stormers,DC=stackstorm,DC=net"],
    "givenName": ["Tomaz"],
    "instanceType": ["4"],
    "lastLogoff": ["0"],
    "lastLogon": ["131144315509626450"],
    "lastLogonTimestamp": ["131326807618683640"],
    "logonCount": ["0"],
    "memberOf": [
        "CN=stormers,OU=groups,DC=stackstorm,DC=net",
        "CN=testers,OU=groups,DC=stackstorm,DC=net",
    ],
    "name": ["Tomaz Muraus"],
    "objectCategory": ["CN=Person,CN=Schema,CN=Configuration,DC=stackstorm,DC=net"],
    "objectClass": ["top", "person", "organizationalPerson", "user"],
    "objectGUID": ["\x1cR\xca\x12\x8a\xda\x8eL\xabe\xcfp\xda\x17H\xf7"],
    "primaryGroupID": ["513"],
    "pwdLastSet": ["131144314220000000"],
    "sAMAccountName": ["tomaz"],
    "sAMAccountType": ["805306368"],
    "sn": ["Muraus"],
    "uSNChanged": ["9835"],
    "uSNCreated": ["3550"],
    "userAccountControl": ["512"],
    "userPrincipalName": ["tomaz@stackstorm.net"],
    "whenChanged": ["20170227145241.0Z"],
    "whenCreated": ["20160731093701.0Z"],
}
LDAP_USER_SEARCH_RESULT = [
    ("cn=Stormin Stanley,cn=users,dc=stackstorm,dc=net", LDAP_USER_INFO_DICT)
]
LDAP_GROUP_SEARCH_RESULT = [
    ("cn=testers,dc=stackstorm,dc=net", ()),
    ("cn=stormers,dc=stackstorm,dc=net", ()),
]


@pytest.fixture
def mock_ldap_bind(mocker: MockerFixture) -> MockType:
    return mocker.patch.object(
        ldap.ldapobject.SimpleLDAPObject,
        "simple_bind_s",
        mocker.MagicMock(return_value=None),  # bind/auth always succeeds
    )


@pytest.fixture
def mock_ldap_auth_failure(mocker: MockerFixture) -> MockType:
    return mocker.patch.object(
        ldap.ldapobject.SimpleLDAPObject,
        "simple_bind_s",
        mocker.MagicMock(
            side_effect=[
                None,  # bind succeeds
                Exception(),  # auth fails
            ]
        ),
    )


@pytest.fixture
def mock_ldap_start_tls(mocker: MockerFixture) -> MockType:
    return mocker.patch.object(
        ldap.ldapobject.SimpleLDAPObject,
        "start_tls_s",
        mocker.MagicMock(return_value=None),
    )


@pytest.fixture
def mock_ldap_search(mocker: MockerFixture, request: pytest.FixtureRequest) -> MockType:
    return mocker.patch.object(
        ldap.ldapobject.SimpleLDAPObject,
        "search_s",
        mocker.MagicMock(side_effect=request.param),
    )


def test_instantiate_no_group_dns_provided():
    # User is member of two of the groups, but none of them are required
    required_group_dns = []
    expected_msg = "One or more user groups must be specified"
    with pytest.raises(ValueError, match=expected_msg):
        ldap_backend.LDAPAuthenticationBackend(
            LDAP_BIND_DN,
            LDAP_BIND_PASSWORD,
            LDAP_BASE_OU,
            required_group_dns,
            LDAP_HOST,
            id_attr=LDAP_ID_ATTR,
        )


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_authenticate(mock_ldap_bind: MockType, mock_ldap_search: MockType):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_authenticate_with_multiple_ldap_hosts(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_MULTIPLE_HOSTS,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_authenticate_without_password(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    with pytest.raises(ValueError):
        backend.authenticate(LDAP_USER_UID, "")


def test_authenticate_failure_bad_bind_cred(mocker: MockerFixture):
    mocker.patch.object(
        ldap.ldapobject.SimpleLDAPObject,
        "simple_bind_s",
        mocker.MagicMock(side_effect=Exception()),  # bind fails
    )
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_authenticate_failure_bad_user_password(
    mock_ldap_auth_failure: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "group_dns_check,mock_ldap_search",
    (
        pytest.param(group_dns_check, [LDAP_USER_SEARCH_RESULT, []], id=group_dns_check)
        for group_dns_check in ("and", "or")
    ),
    indirect=["mock_ldap_search"],
)
def test_authenticate_failure_non_group_member_no_groups(
    group_dns_check: str, mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is not a member of any of the required groups
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check=group_dns_check,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "group_dns_check,mock_ldap_search",
    (
        pytest.param(
            group_dns_check,
            [LDAP_USER_SEARCH_RESULT, [("cn=group1,dc=stackstorm,dc=net", ())]],
            id=group_dns_check,
        )
        for group_dns_check in ("and", "or")
    ),
    indirect=["mock_ldap_search"],
)
def test_authenticate_failure_non_group_member_non_required_group(
    group_dns_check: str, mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is member of a group which is not required
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check=group_dns_check,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group3,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_and_behavior_failure_non_group_member_of_all_required_groups_1(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is member of two of the required groups (1 and 3) but not all three of them
    # (1, 2, 3)
    required_group_dns = [
        "cn=group1,dc=stackstorm,dc=net",
        "cn=group2,dc=stackstorm,dc=net",
        "cn=group3,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="and",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group3,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_and_behavior_failure_non_group_member_of_all_required_groups_2(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is member of two of the groups, but none of them are required
    required_group_dns = [
        "cn=group7,dc=stackstorm,dc=net",
        "cn=group8,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="and",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group2,dc=stackstorm,dc=net", ()),
                ("cn=group3,dc=stackstorm,dc=net", ()),
                ("cn=group4,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_and_behavior_failure_non_group_member_of_all_required_groups_3(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is member of two of the required groups and two non-required, but not
    # all of the required groups
    required_group_dns = [
        "cn=group1,dc=stackstorm,dc=net",
        "cn=group2,dc=stackstorm,dc=net",
        "cn=group5,dc=stackstorm,dc=net",
        "cn=group6,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="and",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group2,dc=stackstorm,dc=net", ()),
                ("cn=group3,dc=stackstorm,dc=net", ()),
                ("cn=group4,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_and_is_default_behavior_non_group_member_of_all_required_groups(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is member of two of the required groups and two non-required, but not
    # all of the required groups
    # Verify "and" is a default group_dns_check_behavior
    required_group_dns = [
        "cn=group1,dc=stackstorm,dc=net",
        "cn=group2,dc=stackstorm,dc=net",
        "cn=group5,dc=stackstorm,dc=net",
        "cn=group6,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, [("cn=group1,dc=stackstorm,dc=net", ())]],),
    indirect=True,
)
def test_authenticate_or_behavior_success_member_of_single_group_1(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is a member of single of possible required groups
    required_group_dns = ["cn=group1,dc=stackstorm,dc=net"]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, [("cn=group1,dc=stackstorm,dc=net", ())]],),
    indirect=True,
)
def test_authenticate_or_behavior_success_member_of_single_group_2(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is a member of single of possible required groups
    required_group_dns = [
        "cn=group1,dc=stackstorm,dc=net",
        "cn=group2,dc=stackstorm,dc=net",
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, [("cn=group3,dc=stackstorm,dc=net", ())]],),
    indirect=True,
)
def test_authenticate_or_behavior_success_member_of_single_group_2b(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is a member of single of possible required groups
    required_group_dns = [
        "cn=group1,dc=stackstorm,dc=net",
        "cn=group2,dc=stackstorm,dc=net",
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group4,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_or_behavior_success_member_of_multiple_groups_1(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is a member of multiple of required groups
    required_group_dns = [
        "cn=group1,dc=stackstorm,dc=net",
        "cn=group2,dc=stackstorm,dc=net",
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
        "cn=group5,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group4,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_or_behavior_success_member_of_multiple_groups_2(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is a member of multiple of required groups
    required_group_dns = [
        "cn=group1,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group3,dc=stackstorm,dc=net", ()),
                ("cn=group6,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_or_behavior_success_member_of_multiple_groups_3(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is a member of multiple of required groups
    required_group_dns = ["cn=group3,dc=stackstorm,dc=net"]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [
                ("cn=group1,dc=stackstorm,dc=net", ()),
                ("cn=group3,dc=stackstorm,dc=net", ()),
                ("cn=group6,dc=stackstorm,dc=net", ()),
            ],
        ],
    ),
    indirect=True,
)
def test_authenticate_or_behavior_success_member_of_multiple_groups_3b(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    # User is a member of multiple of required groups
    required_group_dns = [
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group1,dc=stackstorm,dc=net",
    ]
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_ssl_authenticate(mock_ldap_bind: MockType, mock_ldap_search: MockType):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        port=LDAPS_PORT,
        use_ssl=True,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_ssl_authenticate_failure(
    mock_ldap_auth_failure: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        port=LDAPS_PORT,
        use_ssl=True,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_ssl_authenticate_validate_cert(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        port=LDAPS_PORT,
        use_ssl=True,
        cacert=LDAP_CACERT_REAL_PATH,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_tls_authenticate(
    mock_ldap_start_tls: MockType, mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        use_tls=True,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_tls_authenticate_failure(
    mock_ldap_start_tls: MockType,
    mock_ldap_auth_failure: MockType,
    mock_ldap_search: MockType,
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        use_tls=True,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert not authenticated


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_tls_authenticate_validate_cert(
    mock_ldap_start_tls: MockType, mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        use_tls=True,
        cacert=LDAP_CACERT_REAL_PATH,
        id_attr=LDAP_ID_ATTR,
    )

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_PASSWD)
    assert authenticated


@pytest.mark.parametrize(
    "actual_username,expected_username,mock_ldap_search",
    (
        pytest.param(actual, expected, [LDAP_USER_SEARCH_RESULT, []], id=test_name)
        for test_name, actual, expected in (
            ("only-alpha", "stanleyA", "stanleyA"),
            ("special-chars-unescaped", "stanley!@?.,&", "stanley!@?.,&"),
            # Special characters () should be escaped
            ("parens-escaped-1", "(stanley)", "\\28stanley\\29"),
            # Special characters () should be escaped
            ("parens-escaped-2", "(stanley=)", "\\28stanley=\\29"),
        )
    ),
    indirect=["mock_ldap_search"],
)
def test_special_characters_in_username_are_escaped(
    actual_username: str,
    expected_username: str,
    mock_ldap_bind: MockType,
    mock_ldap_search: MockType,
):
    # User is not a member of any of the required groups
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    backend.authenticate(actual_username, LDAP_USER_BAD_PASSWD)

    call_args_1 = mock_ldap_search.call_args_list[0][0]
    call_args_2 = mock_ldap_search.call_args_list[1][0]

    # First search_s call (find user by uid)
    filter_call_value = call_args_1[2]
    assert filter_call_value == f"uid={expected_username}"

    # Second search_s call (group membership test)
    filter_call_value = call_args_2[2]
    assert f"(memberUid={expected_username})" in filter_call_value


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_get_user(mock_ldap_bind: MockType, mock_ldap_search: MockType):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    user_info = backend.get_user(username=LDAP_USER_UID)
    assert user_info["cn"] == ["Tomaz Muraus"]
    assert user_info["displayName"] == ["Tomaz Muraus"]
    assert user_info["givenName"] == ["Tomaz"]
    assert user_info["primaryGroupID"] == ["513"]


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([2 * LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_get_user_multiple_results(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    user_info = backend.get_user(username=LDAP_USER_UID)
    assert user_info is None


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT, LDAP_GROUP_SEARCH_RESULT],),
    indirect=True,
)
def test_get_user_groups(mock_ldap_bind: MockType, mock_ldap_search: MockType):
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        LDAP_GROUP_DNS,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
    )

    expected = ["cn=testers,dc=stackstorm,dc=net", "cn=stormers,dc=stackstorm,dc=net"]

    groups = backend.get_user_groups(username=LDAP_USER_UID)
    assert groups == expected


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [("cn=group1,dc=stackstorm,dc=net", ())],
            LDAP_USER_SEARCH_RESULT,
            [("cn=group1,dc=stackstorm,dc=net", ())],
        ],
    ),
    indirect=True,
)
def test_authenticate_and_get_user_groups_caching_disabled(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    required_group_dns = ["cn=group1,dc=stackstorm,dc=net"]

    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
        cache_user_groups_response=False,
    )

    assert mock_ldap_search.call_count == 0

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated

    # 1 for user dn search, 1 for groups search
    assert mock_ldap_search.call_count == 2

    user_groups = backend.get_user_groups(username=LDAP_USER_UID)
    assert user_groups == ["cn=group1,dc=stackstorm,dc=net"]
    assert mock_ldap_search.call_count == 4
    assert backend._user_groups_cache is None


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [("cn=group1,dc=stackstorm,dc=net", ())],
            LDAP_USER_SEARCH_RESULT,
            [("cn=group1,dc=stackstorm,dc=net", ())],
        ],
    ),
    indirect=True,
)
def test_authenticate_and_get_user_groups_caching_enabled(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    required_group_dns = ["cn=group1,dc=stackstorm,dc=net"]

    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
        cache_user_groups_response=True,
    )

    assert mock_ldap_search.call_count == 0

    authenticated = backend.authenticate(LDAP_USER_UID, LDAP_USER_BAD_PASSWD)
    assert authenticated
    assert mock_ldap_search.call_count == 2

    user_groups = backend.get_user_groups(username=LDAP_USER_UID)
    assert user_groups == ["cn=group1,dc=stackstorm,dc=net"]
    assert mock_ldap_search.call_count == 2
    assert LDAP_USER_UID in backend._user_groups_cache


@pytest.mark.parametrize(
    "mock_ldap_search",
    ([LDAP_USER_SEARCH_RESULT],),
    indirect=True,
)
def test_get_user_specifying_account_pattern(
    mock_ldap_bind: MockType, mock_ldap_search: MockType, mocker: MockerFixture
):
    expected_username = "unique_username_1"
    required_group_dns = [
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
    ]
    scope = "subtree"
    scope_number = ldap_backend.SEARCH_SCOPES[scope]

    account_pattern = """
    (&
      (objectClass=person)
      (|
        (accountName={username})
        (mail={username})
      )
    )
    """.replace(
        "\n", ""
    ).replace(
        " ", ""
    )
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
    connection = mocker.MagicMock()
    backend._init_connection = mocker.MagicMock(return_value=connection)
    backend.get_user(expected_username)

    connection.search_s.assert_called_once_with(
        LDAP_BASE_OU, scope_number, expected_account_pattern, []
    )


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [("cn=group3,dc=stackstorm,dc=net", ())],
            LDAP_USER_SEARCH_RESULT,
            [("cn=group4,dc=stackstorm,dc=net", ())],
        ],
    ),
    indirect=True,
)
def test_get_user_groups_specifying_group_pattern(
    mock_ldap_bind: MockType, mock_ldap_search: MockType, mocker: MockerFixture
):
    expected_user_dn = "unique_userdn_1"
    expected_username = "unique_username_2"
    required_group_dns = [
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
    ]
    scope = "subtree"
    scope_number = ldap_backend.SEARCH_SCOPES[scope]

    group_pattern = """
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
    """.replace(
        "\n", ""
    ).replace(
        " ", ""
    )
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
    connection = mocker.MagicMock()
    backend._init_connection = mocker.MagicMock(return_value=connection)
    backend._get_user_dn = mocker.MagicMock(return_value=expected_user_dn)

    backend.get_user_groups(expected_username)
    connection.search_s.assert_called_with(
        LDAP_BASE_OU, scope_number, expected_group_pattern, []
    )


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [("cn=group3,dc=stackstorm,dc=net", ())],
            LDAP_USER_SEARCH_RESULT,
            [("cn=group4,dc=stackstorm,dc=net", ())],
        ],
    ),
    indirect=True,
)
def test_get_groups_caching_no_cross_username_cache_pollution(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    required_group_dns = [
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
    ]
    # Test which verifies that cache items are correctly scoped per username
    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
        cache_user_groups_response=True,
    )
    user_groups = backend.get_user_groups(username=LDAP_USER_UID)
    assert user_groups == ["cn=group3,dc=stackstorm,dc=net"]
    assert backend._user_groups_cache[LDAP_USER_UID] == [
        "cn=group3,dc=stackstorm,dc=net"
    ]

    user_groups = backend.get_user_groups(username=LDAP_USER_UID_2)
    assert user_groups == ["cn=group4,dc=stackstorm,dc=net"]
    assert backend._user_groups_cache[LDAP_USER_UID_2] == [
        "cn=group4,dc=stackstorm,dc=net"
    ]


@pytest.mark.parametrize(
    "mock_ldap_search",
    (
        [
            LDAP_USER_SEARCH_RESULT,
            [("cn=group3,dc=stackstorm,dc=net", ())],
            LDAP_USER_SEARCH_RESULT,
            [("cn=group4,dc=stackstorm,dc=net", ())],
        ],
    ),
    indirect=True,
)
def test_get_groups_caching_cache_ttl(
    mock_ldap_bind: MockType, mock_ldap_search: MockType
):
    required_group_dns = [
        "cn=group3,dc=stackstorm,dc=net",
        "cn=group4,dc=stackstorm,dc=net",
    ]

    backend = ldap_backend.LDAPAuthenticationBackend(
        LDAP_BIND_DN,
        LDAP_BIND_PASSWORD,
        LDAP_BASE_OU,
        required_group_dns,
        LDAP_HOST,
        id_attr=LDAP_ID_ATTR,
        group_dns_check="or",
        cache_user_groups_response=True,
        cache_user_groups_cache_ttl=1,
    )
    user_groups = backend.get_user_groups(username=LDAP_USER_UID)
    assert user_groups == ["cn=group3,dc=stackstorm,dc=net"]
    assert LDAP_USER_UID in backend._user_groups_cache
    assert backend._user_groups_cache[LDAP_USER_UID] == [
        "cn=group3,dc=stackstorm,dc=net"
    ]

    # After 1 second, cache entry should expire and it should result in another search_s call
    # which returns group4
    time.sleep(1.5)

    user_groups = backend.get_user_groups(username=LDAP_USER_UID)
    assert user_groups == ["cn=group4,dc=stackstorm,dc=net"]
    assert LDAP_USER_UID in backend._user_groups_cache
    assert backend._user_groups_cache[LDAP_USER_UID] == [
        "cn=group4,dc=stackstorm,dc=net"
    ]

    # Cache should now be empty
    time.sleep(1.5)
    assert LDAP_USER_UID not in backend._user_groups_cache
