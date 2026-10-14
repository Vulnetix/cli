<?php
$ds = ldap_connect('ldap://ldap.corp.local');
ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
~>$bound = ldap_bind($ds);
~>if (!@ldap_bind( $ds )) {
    die('bind failed');
}
~>$r = ldap_bind($ds, null, null);
