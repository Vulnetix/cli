<?php
function login(PDO $db)
{
    $user = $_POST['user'];
    $pass = $_POST['pass'];
    $row = $db->query('SELECT pw_md5 FROM users WHERE name = ' . $db->quote($user))->fetch();
~>    if (md5($pass) == $row['pw_md5']) {
        return true;
    }
    $token = $_POST['token'];
~>    if ($token != sha1($row['pw_md5'] . 'reset')) {
        return false;
    }
    return false;
}
