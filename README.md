# LDAP Authentication Backend for StackStorm Enterprise Edition

## Requirements

Ubuntu / Debian

```bash
sudo apt-get install -y python-dev libldap2-dev libsasl2-dev libssl-dev ldap-utils
```

CentOS / RHEL / Fedora

```bash
sudo dnf install python2-devel python3-devel openldap-devel
```

## Configuration Options

| option                     | required | default | description                                                                                                                    |
|----------------------------|----------|---------|--------------------------------------------------------------------------------------------------------------------------------|
| bind_dn                    | yes      |         | DN of the service account to bind with the LDAP server                                                                         |
| bind_password              | yes      |         | Password of the service account                                                                                                |
| base_ou                    | yes      |         | Base OU to search for user and group entries                                                                                   |
| group_dns                  | yes      |         | Which groups user must be member of to be granted access                                                                       |
| group_dns_check            | no       | and     | What kind of check to perform when validating user group membership (``and`` / ``or``). When ``and`` behavior is used, user needs to be part of all the specified groups and when ``or`` behavior is used, user needs to be part of at least one or more of the specified groups.                                                         |
| host                       | yes      |         | Hostname of the LDAP server                                                                                                    |
| port                       | yes      |         | Port of the LDAP server                                                                                                        |
| use_ssl                    | no       | false   | Use LDAPS to connect                                                                                                           |
| use_tls                    | no       | false   | Start TLS on LDAP to connect                                                                                                   |
| cacert                     | no       | None    | Path to the CA cert used to validate certificate                                                                               |
| id_attr                    | no       | uid     | Field name of the user ID attribute                                                                                            |
| scope                      | no       | subtree | Search scope (base, onelevel, or subtree)                                                                                      |
| network_timeout            | no       | 10.0    | Timeout for network operations (in seconds)                                                                                    |
| chase_referrals            | no       | false   | True if the referrals should be automatically chased within the underlying LDAP C lib                                          |
| debug                      | no       | false   | Enable debug mode. When debug mode is enabled all the calls (including the results) to LDAP server are logged                  |
| client_options             | no       |         | A dictionary with additional Python LDAP client options which can be passed to ``set_connection()`` method                     |
| cache_user_groups_response | no       | true    | When true, LDAP user groups response is cached for 120 seconds (by default) in memory. This decreases load on LDAP server and increases performance when remote LDAP group to RBAC role sync is enabled and / or when the same user authenticates concurrency in a short time frame. Keep in mind that even when this feature is enabled, single (authenticate) request to LDAP server will still be performed when user authenticates to st2auth - authentication information is not cached - only user groups are cached.  |
| cache_user_groups_ttl      | no       | 120     | How long (in seconds)                                                                                                          |

## Configuration Example

Please refer to the [standalone mode](http://docs.stackstorm.com/config/authentication.html#setup-standalone-mode) in the configuration section for authentication for basic setup concept. The following is an example of the auth section in the StackStorm configuration file for the LDAP backend.

```ini
[auth]
mode = standalone
backend = ldap
backend_kwargs = {"bind_dn": "CN=st2admin,ou=users,dc=example,dc=com", "bind_password": "foobar123", "base_ou": "dc=example,dc=com", "group_dns": ["CN=st2users,ou=groups,dc=example,dc=com", "CN=st2developers,ou=groups,dc=example,dc=com"], "host": "identity.example.com", "port": 636, "use_ssl": true, "cacert": "/path/to/cacert.pem"}
enable = True
debug = False
use_ssl = True
cert = /path/to/mycert.crt
key = /path/to/mycert.key
logging = /path/to/st2auth.logging.conf
api_url = http://myhost.example.com:9101/
```

Note: Key in the ``client_options`` dictionary must be an integer representing a LDAP constant option value.

For example:

```ini
backend_kwargs = {..., "client_options": {"20482": 9}}
```

In this case, "20482" represents ``ldap.OPT_TIMEOUT`` option.

To retrieve a integer value of a particular client option constant, you can run the following code:

```python
import ldap
print(ldap.OPT_TIMEOUT)
```

## Running tests

Unit tests:

```bash
make unit-tests
```

## Copyright, License, and Contributors Agreement

Copyright 2015-2020 Extreme Networks, Inc.

Copyright 2020 StackStorm, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this work except in compliance with the License. You may obtain a copy of the License in the [LICENSE](LICENSE) file, or at:

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

By contributing you agree that these contributions are your own (or approved by your employer) and you grant a full, complete, irrevocable copyright license to all users and developers of the project, present and future, pursuant to the license of the project.
