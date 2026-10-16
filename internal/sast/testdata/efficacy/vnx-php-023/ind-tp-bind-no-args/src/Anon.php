<?php
$conn = ldap_connect('ldaps://ldap.example.com');
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
~>$ok = ldap_bind($conn);
