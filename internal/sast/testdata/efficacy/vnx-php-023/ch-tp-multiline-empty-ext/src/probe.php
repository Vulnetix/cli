<?php
$link = ldap_connect('ldaps://ldap.corp.example');

~>$ok = ldap_bind(
    $link,
    'cn=monitor,dc=corp,dc=example',
    ''
);

~>$res = ldap_bind_ext($link, 'cn=probe,dc=corp,dc=example', "", []);

$pw = '';
~>ldap_bind($link, 'cn=status,dc=corp,dc=example', $pw);
