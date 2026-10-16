<?php
$conn = ldap_connect($host);
~>if (ldap_bind($conn, 'cn=reader,dc=example,dc=com', '')) {
    $r = ldap_search($conn, 'dc=example,dc=com', '(objectClass=*)');
}
