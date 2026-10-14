<?php

function login($db, $user, $pass) {
~>    $pass = md5( $pass );
    return $db->query("SELECT * FROM users WHERE user = ? AND password = ?", [$user, $pass]);
}

function change($db, $pass_new, $pass_conf) {
~>    $pass_new = md5($pass_new);
~>    $pass_conf = sha1($pass_conf);
    return $pass_new === $pass_conf;
}

function salted($password, $salt) {
~>    return hash('sha256', $salt . $password);
}
