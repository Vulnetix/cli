<?php
// Anonymous binds such as ldap_bind($conn) are rejected by the server.
return [
    'host' => env('LDAP_HOST', 'ldaps://ldap.corp.example'),
    'bind_dn' => env('LDAP_BIND_DN'),
    'bind_password' => env('LDAP_BIND_PASSWORD'),
    'note' => 'do not call ldap_bind($link, null, null)',
];
