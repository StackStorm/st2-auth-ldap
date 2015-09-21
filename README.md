# LDAP Authentication Backend for StackStorm Enterprise Edition

[![Build Status](https://magnum.travis-ci.com/StackStorm/st2-enterprise-auth-backend-ldap.svg?token=9VSoAP6mbfNshpDaAKvx&branch=master)](https://magnum.travis-ci.com/StackStorm/st2-enterprise-auth-backend-ldap) [![IRC](https://img.shields.io/irc/%23stackstorm.png)](http://webchat.freenode.net/?channels=stackstorm)

### Requirements
```
sudo apt-get install -y python-dev libldap2-dev libsasl2-dev libssl-dev ldap-utils
```

### Configuration Options

| option   | required | default | description                               |
|----------|----------|---------|-------------------------------------------|
| users_ou | yes      |         | OU of the user accounts                   |
| host     | yes      |         | Hostname of the LDAP server               |
| port     | yes      |         | Port of the LDAP server                   |
| use_ssl  | no       | false   | Use LDAPS to connect                      |
| use_tls  | no       | false   | Start TLS on LDAP to connect              |
| cacert   | no       | None    | CA cert to validate certificate           |
| id_attr  | no       | uid     | Field name of the user ID attribute       |
| scope    | no       | subtree | Search scope (base, onelevel, or subtree) |

### Configuration Example

Please refer to the [standalone mode](http://docs.stackstorm.com/config/authentication.html#setup-standalone-mode) in the configuration section for authentication for basic setup concept. The following is an example of the auth section in the StackStorm configuration file for the LDAP backend.

```
[auth]
mode = standalone
backend = ldap
backend_kwargs = {"users_ou": "ou=users,dc=example,dc=com", "host": "identity.example.com", "port": 636, "use_ssl": true, "cacert": "/path/to/cacert.pem"}
enable = True
debug = False
use_ssl = True
cert = /path/to/mycert.crt
key = /path/to/mycert.key
logging = /path/to/st2auth.logging.conf
api_url = http://myhost.example.com:9101/
```
