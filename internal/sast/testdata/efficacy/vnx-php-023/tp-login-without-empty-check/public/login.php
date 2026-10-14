<?php
$user = $_POST['username'];
$pass = $_POST['password'];
$ds = ldap_connect('ldaps://ldap.corp.local');
$dn = 'uid=' . ldap_escape($user, '', LDAP_ESCAPE_DN) . ',ou=people,dc=corp,dc=local';
~>if (ldap_bind($ds, $dn, $pass)) {
    $_SESSION['user'] = $user;
    header('Location: /home');
}
