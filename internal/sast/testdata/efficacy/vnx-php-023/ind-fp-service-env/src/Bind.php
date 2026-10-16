<?php
$ds = ldap_connect(getenv('LDAP_URI'));
ldap_bind($ds, getenv('LDAP_BIND_DN'), getenv('LDAP_BIND_PASSWORD'));
