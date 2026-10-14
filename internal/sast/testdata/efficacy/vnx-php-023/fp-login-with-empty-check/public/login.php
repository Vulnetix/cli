<?php
$user = $_POST['username'];
$pass = $_POST['password'];
if (empty($pass) || $user === '') {
    http_response_code(400);
    exit('missing credentials');
}
$ds = ldap_connect('ldaps://ldap.corp.local');
if (ldap_bind($ds, 'uid=' . ldap_escape($user, '', LDAP_ESCAPE_DN) . ',ou=people,dc=corp,dc=local', $pass)) {
    $_SESSION['user'] = $user;
}
$p2 = $_POST['pin'];
if (strlen($p2) > 0 && ldap_bind($ds, $dn2, $p2)) {
    echo 'ok';
}
