# Copyright (C) 2019 Extreme Networks, Inc - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly
# prohibited. Proprietary and confidential. See the LICENSE file
# included with this work for details.

from __future__ import absolute_import

from .ldap_backend import LDAPAuthenticationBackend

__version__ = '3.2.0'

__all__ = [
    'LDAPAuthenticationBackend'
]
