# LDAP Authentication Backend for StackStorm Enterprise Edition

[![Circle CI Build Status](https://circleci.com/gh/StackStorm/st2-enterprise-auth-backend-ldap.svg?style=shield&circle-token=c0124395bc8e6563655ed40dc2e72b0beb44fae3)](https://circleci.com/gh/StackStorm/st2-enterprise-auth-backend-ldap)
[![IRC](https://img.shields.io/irc/%23stackstorm.png)](http://webchat.freenode.net/?channels=stackstorm)

## Requirements

```bash
sudo apt-get install -y python-dev libldap2-dev libsasl2-dev libssl-dev ldap-utils
```

## Configuration Options

| option          | required | default | description                                                                                                                    |
|-----------------|----------|---------|--------------------------------------------------------------------------------------------------------------------------------|
| bind_dn         | yes      |         | DN of the service account to bind with the LDAP server                                                                         |
| bind_password   | yes      |         | Password of the service account                                                                                                |
| base_ou         | yes      |         | Base OU to search for user and group entries                                                                                   |
| group_dns       | yes      |         | User must be member of this list of groups to get access                                                                       |
| host            | yes      |         | Hostname of the LDAP server                                                                                                    |
| port            | yes      |         | Port of the LDAP server                                                                                                        |
| use_ssl         | no       | false   | Use LDAPS to connect                                                                                                           |
| use_tls         | no       | false   | Start TLS on LDAP to connect                                                                                                   |
| cacert          | no       | None    | Path to the CA cert used to validate certificate                                                                               |
| id_attr         | no       | uid     | Field name of the user ID attribute                                                                                            |
| scope           | no       | subtree | Search scope (base, onelevel, or subtree)                                                                                      |
| network_timeout | no       | 10.0    | Timeout for network operations (in seconds)                                                                                    |
| chase_referrals | no       | false   | True if the referrals should be automatically chased within the underlying LDAP C lib                                          |
| debug           | no       | false   | Enable debug mode. When debug mode is enabled all the calls (including the results) to LDAP server are logged                  |

## Configuration Example

Please refer to the [standalone mode](http://docs.stackstorm.com/config/authentication.html#setup-standalone-mode) in the configuration section for authentication for basic setup concept. The following is an example of the auth section in the StackStorm configuration file for the LDAP backend.

```
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

## Running tests

Unit tests:

```bash
make unit-tests
```
