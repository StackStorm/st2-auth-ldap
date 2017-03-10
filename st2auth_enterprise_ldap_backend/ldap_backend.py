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

# pylint: disable=no-member

from __future__ import absolute_import

import os
import logging

import ldap
import ldapurl

__all__ = [
    'LDAPAuthenticationBackend'
]

LOG = logging.getLogger(__name__)

SEARCH_SCOPES = {
    'base': ldapurl.LDAP_SCOPE_BASE,
    'onelevel': ldapurl.LDAP_SCOPE_ONELEVEL,
    'subtree': ldapurl.LDAP_SCOPE_SUBTREE
}


class LDAPAuthenticationBackend(object):

    def __init__(self, bind_dn, bind_password, base_ou, group_dns, host, port=389,
                 scope='subtree', id_attr='uid', use_ssl=False, use_tls=False,
                 cacert=None, network_timeout=10.0, debug=False):

        if not bind_dn:
            raise ValueError('Bind DN to query the LDAP server is not provided.')

        if not bind_password:
            raise ValueError('Password for the bind DN to query the LDAP server is not provided.')

        if not host:
            raise ValueError('Hostname for the LDAP server is not provided.')

        self._bind_dn = bind_dn
        self._bind_password = bind_password
        self._host = host

        if port:
            self._port = port
        elif not port and not use_ssl:
            LOG.warn('Default port 389 is used for the LDAP query.')
            self._port = 389
        elif not port and use_ssl:
            LOG.warn('Default port 636 is used for the LDAP query over SSL.')
            self._port = 636

        if use_ssl and use_tls:
            raise ValueError('SSL and TLS cannot be both true.')

        if cacert and not os.path.isfile(cacert):
            raise ValueError('Unable to find the cacert file "%s" for the LDAP connection.' %
                             (cacert))

        self._use_ssl = use_ssl
        self._use_tls = use_tls
        self._cacert = cacert
        self._network_timeout = network_timeout
        self._debug = debug

        if not id_attr:
            LOG.warn('Default to "uid" for the user attribute in the LDAP query.')

        if not base_ou:
            raise ValueError('Base OU for the LDAP query is not provided.')

        if scope not in SEARCH_SCOPES.keys():
            raise ValueError('Scope value for the LDAP query must be one of '
                             '%s.' % str(SEARCH_SCOPES.keys()))

        self._id_attr = id_attr or 'uid'
        self._base_ou = base_ou
        self._scope = SEARCH_SCOPES[scope]

        if not group_dns:
            raise ValueError('One or more user groups must be specified.')

        self._group_dns = group_dns

    def _init_connection(self):
        # Use CA cert bundle to validate certificate if present.
        if self._use_ssl or self._use_tls:
            if self._cacert:
                ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self._cacert)
            else:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        if self._debug:
            trace_level = 2
        else:
            trace_level = 0

        # Setup connection and options.
        protocol = 'ldaps' if self._use_ssl else 'ldap'
        endpoint = '%s://%s:%d' % (protocol, self._host, int(self._port))
        connection = ldap.initialize(endpoint, trace_level=trace_level)
        connection.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        connection.set_option(ldap.OPT_REFERRALS, 0)
        connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        connection.set_option(ldap.OPT_NETWORK_TIMEOUT, self._network_timeout)

        if self._use_tls:
            connection.start_tls_s()

        return connection

    def _clear_connection(self, connection):
        if connection:
            connection.unbind_s()

    def authenticate(self, username, password):
        connection = None

        try:
            # Instantiate connection object and bind with service account.
            try:
                connection = self._init_connection()
                connection.simple_bind_s(self._bind_dn, self._bind_password)
            except Exception:
                LOG.exception('Failed to bind with "%s".' % self._bind_dn)
                return False

            # Search for user and fetch the DN of the record.
            try:
                query = '%s=%s' % (self._id_attr, username)
                result = connection.search_s(self._base_ou, self._scope, query, [])
                entries = [entry for entry in result if entry[0] is not None] if result else []

                if len(entries) <= 0:
                    LOG.exception('Unable to identify user for "%s".' % query)
                    return False

                if len(entries) > 1:
                    LOG.exception('More than one users identified for "%s".' % query)
                    return False

                user_dn = entries[0][0]
            except Exception:
                LOG.exception('Unexpected error when querying for user "%s".' % username)
                return False

            # Search if user is member of pre-defined groups.
            # The query on member is included for groupOfNames.
            # The query on uniqueMember is included for groupOfUniqueNames.
            # The query on memberUid is included for posixGroup.
            try:
                query_str = '(|(&(objectClass=*)(|(member={0})(uniqueMember={0})(memberUid={1}))))'
                query = query_str.format(user_dn, username)
                result = connection.search_s(self._base_ou, self._scope, query, [])

                if result:
                    user_groups = [entry[0] for entry in result if entry[0] is not None]
                else:
                    user_groups = []

                # Assume group entries are not case sensitive.
                user_groups = set([entry.lower() for entry in user_groups])
                required_groups = set([entry.lower() for entry in self._group_dns])

                if not required_groups.issubset(user_groups):
                    msg = ('Unable to verify membership for user "%s (required_groups=%s,'
                           'actual_groups=%s)".' % (username, str(required_groups),
                                                    str(user_groups)))
                    LOG.exception(msg)
                    return False
            except Exception:
                LOG.exception('Unexpected error when querying membership for user "%s".' % username)
                return False

            self._clear_connection(connection)

            # Authenticate with the user DN and password.
            try:
                connection = self._init_connection()
                connection.simple_bind_s(user_dn, password)
                LOG.info('Successfully authenticated user "%s".' % username)
                return True
            except Exception:
                LOG.exception('Failed authenticating user "%s".' % username)
                return False
        except ldap.LDAPError:
            LOG.exception('Unexpected LDAP error.')
            return False
        finally:
            self._clear_connection(connection)

        return False

    def get_user(self, username):
        pass
