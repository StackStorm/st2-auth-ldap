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

    def __init__(self, users_ou, host, port=389, scope='subtree',
                 id_attr='uid', use_ssl=False, use_tls=False, cacert=None, bind_user=None, bind_pw=None):

        if not host:
            raise ValueError('Hostname for the LDAP server is not provided.')

        self._host = host
        self._bind_pw = bind_pw
        self._bind_user = bind_user

        if port:
            self._port = port
        elif not port and not use_ssl:
            LOG.warn('Default port 389 is used for the LDAP query.')
            self._port = 389
        elif not port and use_ssl:
            LOG.warn('Default port 636 is used for the LDAP query over SSL.')
            self._port = 636

        if not users_ou:
            raise ValueError('Users OU for the LDAP query is not provided.')

        self._users_ou = users_ou

        if scope not in SEARCH_SCOPES.keys():
            raise ValueError('Scope value for the LDAP query must be one of '
                             '%s.' % str(SEARCH_SCOPES.keys()))

        self._scope = SEARCH_SCOPES[scope]

        if not id_attr:
            LOG.warn('Default to "uid" for the user attribute in the LDAP query.')

        self._id_attr = id_attr or 'uid'

        if use_ssl and use_tls:
            raise ValueError('SSL and TLS cannot be both true.')

        self._use_ssl = use_ssl
        self._use_tls = use_tls

        if cacert and not os.path.isfile(cacert): 
            raise ValueError('Unable to find the cacert file "%s" for the LDAP connection.' % cacert)

        self._cacert = cacert

    def authenticate(self, username, password):
        try:
            # Use CA cert bundle to validate certificate if present.
            if self._use_ssl or self._use_tls:
                if self._cacert:
                    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self._cacert)
                else:
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
         
            # Setup connection and options.
            protocol = 'ldaps' if self._use_ssl else 'ldap'
            endpoint = '%s://%s:%d' % (protocol, self._host, self._port)
            connection = ldap.initialize(endpoint)
            connection.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            connection.set_option(ldap.OPT_REFERRALS, 0)
            connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)

            if self._use_tls:
                connection.start_tls_s()
 
            try:
                # Bind using given username and password.
                user_dn = '%s=%s,%s' % (self._id_attr, username, self._users_ou)

                if self._bind_user is not None:
                    connection.bind(self._bind_user, self._bind_pw)
                    LOG.info("Successfully authenticated bind")
                else:
                    connection.simple_bind_s(user_dn, password)
                LOG.info('Successfully authenticated user "%s".' % username)
                return True
            except Exception as e:
                LOG.exception('Failed authenticating user "%s".' % username)
                return False
            finally:
                connection.unbind_s()
        except ldap.LDAPError as e:
            LOG.exception('Unexpected LDAP configuration or connection error.')
            return False

    def get_user(self, username):
        pass