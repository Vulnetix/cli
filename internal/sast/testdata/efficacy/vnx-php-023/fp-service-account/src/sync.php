<?php
$ds = ldap_connect(getenv('LDAP_HOST'));
ldap_bind($ds, getenv('LDAP_BIND_DN'), getenv('LDAP_BIND_PASSWORD'));
$password = $config['ldap']['password'];
ldap_bind($ds, $config['ldap']['dn'], $password);
ldap_bind($ds, 'cn=svc,dc=corp,dc=local', $this->secrets->get('ldap'));
ldap_bind_ext($ds, $bindDn, $bindPw, [['oid' => LDAP_CONTROL_PASSWDPOLICYREQUEST]]);
