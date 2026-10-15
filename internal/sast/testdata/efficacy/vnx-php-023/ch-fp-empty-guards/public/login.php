<?php
$ds = ldap_connect('ldaps://ldap.corp.example');

function try_login($ds) {
    $user = $_POST['user'] ?? '';
    $pass = $_POST['pass'] ?? '';
    if ($user === '' || $pass === '') {
        return false;
    }
    $dn = 'uid=' . ldap_escape($user, '', LDAP_ESCAPE_DN) . ',ou=people,dc=corp,dc=example';
    return @ldap_bind($ds, $dn, $pass);
}

function try_login_strlen($ds) {
    $secret = $_POST['secret'];
    if (strlen($secret) === 0) {
        die('password required');
    }
    return ldap_bind($ds, 'uid=svc,dc=corp,dc=example', $secret);
}

function try_login_empty($ds) {
    $pw = filter_input(INPUT_POST, 'pw');
    if (empty($pw)) {
        return false;
    }
    return ldap_bind($ds, 'uid=web,dc=corp,dc=example', $pw);
}
