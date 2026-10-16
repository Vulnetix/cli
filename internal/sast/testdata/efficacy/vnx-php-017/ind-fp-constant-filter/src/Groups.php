<?php
// Lists all groups; no request input is involved.
$res = ldap_search($conn, 'ou=groups,dc=example,dc=com', '(objectClass=groupOfNames)', ['cn']);
$entries = ldap_get_entries($conn, $res);
foreach ($entries as $e) {
    echo $e['cn'][0], "\n";
}
// ldap_search($c, $b, '(cn=' . $_GET['x'] . ')') would be unsafe
