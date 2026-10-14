<?php
$ds = ldap_connect('ldap://dir.internal');
ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
~>$sr = ldap_search($ds, 'ou=people,dc=corp,dc=local', "(uid=" . $_POST['username'] . ")");
$entries = ldap_get_entries($ds, $sr);
if ($entries['count'] === 1) {
    $_SESSION['dn'] = $entries[0]['dn'];
}
