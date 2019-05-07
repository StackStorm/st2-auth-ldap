# Copyright (C) 2019 Extreme Networks, Inc - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential.
# See the LICENSE file included with this work for details.

# pylint: disable=no-member

from __future__ import absolute_import

import os
import logging

import ldap
import ldap.filter
import ldapurl

from cachetools import TTLCache

from st2auth.backends.constants import AuthBackendCapability

__all__ = [
    'LDAPAuthenticationBackend'
]

LOG = logging.getLogger(__name__)

SEARCH_SCOPES = {
    'base': ldapurl.LDAP_SCOPE_BASE,
    'onelevel': ldapurl.LDAP_SCOPE_ONELEVEL,
    'subtree': ldapurl.LDAP_SCOPE_SUBTREE
}

VALID_GROUP_DNS_CHECK_VALUES = [
    'and',
    'or'
]

# The query on member is included for groupOfNames.
# The query on uniqueMember is included for groupOfUniqueNames.
# The query on memberUid is included for posixGroup.
#
# Note: To avoid injection attacks the final query needs to be assembled ldap.filter.filter_format
# method and *NOT* by doing simple string formating / concatenation (method ensures filter values
# are correctly escaped).
USER_GROUP_MEMBERSHIP_QUERY = '(|(&(objectClass=*)(|(member=%s)(uniqueMember=%s)(memberUid=%s))))'


class LDAPAuthenticationBackend(object):
    CAPABILITIES = (
        AuthBackendCapability.CAN_AUTHENTICATE_USER,
        AuthBackendCapability.HAS_USER_INFORMATION,
        AuthBackendCapability.HAS_GROUP_INFORMATION
    )

    def __init__(self, bind_dn, bind_password, base_ou, group_dns, host, port=389,
                 scope='subtree', id_attr='uid', use_ssl=False, use_tls=False,
                 cacert=None, network_timeout=10.0, chase_referrals=False, debug=False,
                 client_options=None, group_dns_check='and',
                 cache_user_groups_response=True, cache_user_groups_cache_ttl=120,
                 cache_user_groups_cache_max_size=100):

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
        self._chase_referrals = chase_referrals
        self._debug = debug
        self._client_options = client_options

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

        if group_dns_check not in VALID_GROUP_DNS_CHECK_VALUES:
            valid_values = ', '.join(VALID_GROUP_DNS_CHECK_VALUES)
            raise ValueError('Invalid value "%s" for group_dns_check option. Valid values are: '
                             '%s.' % (group_dns_check, valid_values))

        self._group_dns_check = group_dns_check
        self._group_dns = group_dns

        self._cache_user_groups_response = cache_user_groups_response
        self._cache_user_groups_cache_ttl = int(cache_user_groups_cache_ttl)
        self._cache_user_groups_cache_max_size = int(cache_user_groups_cache_max_size)

        # Cache which stores LDAP groups response for a particular user
        if self._cache_user_groups_response:
            self._user_groups_cache = TTLCache(maxsize=self._cache_user_groups_cache_max_size,
                                               ttl=self._cache_user_groups_cache_ttl)
        else:
            self._user_groups_cache = None

    def authenticate(self, username, password):
        connection = None

        if not password:
            raise ValueError('password cannot be empty')

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
                user_dn = self._get_user_dn(connection=connection, username=username)
            except ValueError as e:
                LOG.exception(str(e))
                return False
            except Exception:
                LOG.exception('Unexpected error when querying for user "%s".' % username)
                return False

            # Search if user is member of pre-defined groups.
            try:
                user_groups = self._get_groups_for_user(connection=connection, user_dn=user_dn,
                                                        username=username)

                # Assume group entries are not case sensitive.
                user_groups = set([entry.lower() for entry in user_groups])
                required_groups = set([entry.lower() for entry in self._group_dns])

                result = self._verify_user_group_membership(username=username,
                                                            required_groups=required_groups,
                                                            user_groups=user_groups,
                                                            check_behavior=self._group_dns_check)
                if not result:
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
        """
        Retrieve user information.

        :rtype: ``dict``
        """
        connection = None

        try:
            connection = self._init_connection()
            connection.simple_bind_s(self._bind_dn, self._bind_password)

            _, user_info = self._get_user(connection=connection, username=username)
        except Exception:
            LOG.exception('Failed to retrieve details for user "%s"' % (username))
            return None
        finally:
            self._clear_connection(connection)

        user_info = dict(user_info)
        return user_info

    def get_user_groups(self, username):
        """
        Return a list of all the groups user is a member of.

        :rtype: ``list`` of ``str``
        """
        # First try to get result from a local in-memory cache
        groups = self._get_user_groups_from_cache(username=username)
        if groups is not None:
            return groups

        connection = None

        try:
            connection = self._init_connection()
            connection.simple_bind_s(self._bind_dn, self._bind_password)

            user_dn = self._get_user_dn(connection=connection, username=username)
            groups = self._get_groups_for_user(connection=connection, user_dn=user_dn,
                                               username=username)
        except Exception:
            LOG.exception('Failed to retrieve groups for user "%s"' % (username))
            return None
        finally:
            self._clear_connection(connection)

        # Store result in cache (if caching is enabled)
        self._set_user_groups_in_cache(username=username, groups=groups)

        return groups

    def _init_connection(self):
        """
        Initialize connection to the LDAP server.
        """
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
        connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        connection.set_option(ldap.OPT_NETWORK_TIMEOUT, self._network_timeout)

        if self._chase_referrals:
            connection.set_option(ldap.OPT_REFERRALS, 1)
        else:
            connection.set_option(ldap.OPT_REFERRALS, 0)

        client_options = self._client_options or {}
        for option_name, option_value in client_options.items():
            connection.set_option(int(option_name), option_value)

        if self._use_tls:
            connection.start_tls_s()

        return connection

    def _clear_connection(self, connection):
        """
        Unbind and close connection to the LDAP server.
        """
        if connection:
            connection.unbind_s()

    def _get_user_dn(self, connection, username):
        user_dn, _ = self._get_user(connection=connection, username=username)
        return user_dn

    def _get_user(self, connection, username):
        """
        Retrieve LDAP user record for the provided username.

        Note: This method escapes ``username`` so it can safely be used as a filter in the query.

        :rtype: ``tuple`` (``user_dn``, ``user_info_dict``)
        """
        username = ldap.filter.escape_filter_chars(username)
        query = '%s=%s' % (self._id_attr, username)
        result = connection.search_s(self._base_ou, self._scope, query, [])

        if result:
            entries = [entry for entry in result if entry[0] is not None]
        else:
            entries = []

        if len(entries) <= 0:
            msg = ('Unable to identify user for "%s".' % (query))
            raise ValueError(msg)

        if len(entries) > 1:
            msg = ('More than one users identified for "%s".' % (query))
            raise ValueError(msg)

        user_tuple = entries[0]
        return user_tuple

    def _get_groups_for_user(self, connection, user_dn, username):
        """
        Return a list of all the groups user is a member of.

        :rtype: ``list`` of ``str``
        """
        # First try to get result from a local in memory cache
        groups = self._get_user_groups_from_cache(username=username)
        if groups is not None:
            return groups

        filter_values = [user_dn, user_dn, username]
        query = ldap.filter.filter_format(USER_GROUP_MEMBERSHIP_QUERY, filter_values)
        result = connection.search_s(self._base_ou, self._scope, query, [])

        if result:
            groups = [entry[0] for entry in result if entry[0] is not None]
        else:
            groups = []

        # Store result in cache (if caching is enabled)
        self._set_user_groups_in_cache(username=username, groups=groups)

        return groups

    def _verify_user_group_membership(self, username, required_groups, user_groups,
                                      check_behavior='and'):
        """
        Validate that the user is a member of required groups based on the check behavior defined
        in the config (and / or).
        """

        if check_behavior == 'and':
            additional_msg = ('user needs to be member of all the following groups "%s" for '
                              'authentication to succeeed')
        elif check_behavior == 'or':
            additional_msg = ('user needs to be member of one or more of the following groups "%s" '
                              'for authentication to succeeed')

        additional_msg = additional_msg % (str(list(required_groups)))

        LOG.debug('Verifying user group membership using "%s" behavior (%s)' %
                  (check_behavior, additional_msg))

        if check_behavior == 'and':
            if required_groups.issubset(user_groups):
                return True
        elif check_behavior == 'or':
            if required_groups.intersection(user_groups):
                return True

        msg = ('Unable to verify membership for user "%s (required_groups=%s,'
               'actual_groups=%s,check_behavior=%s)".' % (username, str(required_groups),
                                                          str(user_groups), check_behavior))
        LOG.exception(msg)

        # Final safe guard
        return False

    def _get_user_groups_from_cache(self, username):
        """
        Get value from per-user group cache (if caching is enabled).
        """
        if not self._cache_user_groups_response:
            return None

        LOG.debug('Getting LDAP groups for user "%s" from cache' % (username))
        result = self._user_groups_cache.get(username, None)

        if result is None:
            LOG.debug('LDAP groups cache for user "%s" is empty' % (username))
        else:
            LOG.debug('Found LDAP groups cache for user "%s"' % (username))

        return result

    def _set_user_groups_in_cache(self, username, groups):
        """
        Store value in per-user group cache (if caching is enabled).
        """
        if not self._cache_user_groups_response:
            return None

        LOG.debug('Storing groups for user "%s" in cache' % (username))
        self._user_groups_cache[username] = groups
