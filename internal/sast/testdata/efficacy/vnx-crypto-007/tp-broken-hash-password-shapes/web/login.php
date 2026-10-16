<?php
function login($db, $salt, $password)
{
~>    $given = md5($_POST['password']);
~>    $hash = sha1($salt . $password);
~>    $pass = md5( $pass );
    return $db->fetch('SELECT id FROM users WHERE pass = ? OR pass = ?', [$given, $hash]);
}
