<?php
require_once __DIR__ . '/bootstrap.php';

$conn = ldap_connect(LDAP_URI);
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_bind($conn, LDAP_SVC_DN, LDAP_SVC_PW);

~>$entry = ldap_read($conn, 'uid=' . $_COOKIE['uid'] . ',ou=people,dc=example,dc=org', '(objectClass=*)');
$data = ldap_get_entries($conn, $entry);
echo htmlspecialchars($data[0]['cn'][0]);
