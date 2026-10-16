<?php
$userDn = 'uid=' . ldap_escape($u, '', LDAP_ESCAPE_DN) . ',ou=people,dc=example,dc=com';
~>$bound = @ldap_bind($link, $userDn, null);
