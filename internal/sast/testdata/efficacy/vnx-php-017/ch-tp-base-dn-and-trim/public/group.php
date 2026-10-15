<?php
$ds = ldap_connect('ldaps://ldap.corp.example');
~>$entry = ldap_read($ds, "cn=" . $_REQUEST['group'] . ",ou=groups,dc=corp,dc=example", '(objectClass=*)');

$name = trim($_COOKIE['member']);
$f = "(memberUid={$name})";
~>$members = ldap_list($ds, 'ou=groups,dc=corp,dc=example', $f);
