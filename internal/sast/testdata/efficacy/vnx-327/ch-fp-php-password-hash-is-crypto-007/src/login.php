<?php

function store_user($db, $email, $password)
{
    $salt = bin2hex(random_bytes(8));
    $hash = sha1($salt . $password);
    $db->insert('users', ['email' => $email, 'salt' => $salt, 'hash' => $hash]);
}

function login($db)
{
    $given = md5($_POST['password']);
    return $db->fetch('SELECT id FROM users WHERE pass = ?', [$given]);
}
