<?php
function register($db, $name) {
    $cred = $_POST['password'];
    $confirm = $_POST['confirm'];
~>    $password_hash = sha1($cred);
    $db->insert('users', ['name' => $name, 'hash' => $hash]);
}
