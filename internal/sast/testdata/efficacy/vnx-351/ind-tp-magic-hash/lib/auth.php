<?php

function check_login(PDO $db): bool
{
    $stmt = $db->prepare('SELECT pw_md5 FROM users WHERE name = ?');
    $stmt->execute([$_POST['user']]);
    $row = $stmt->fetch();
~>    return md5($_POST['pass']) == $row['pw_md5'];
}

function check_token(string $stored): bool
{
~>    return hash('sha256', $_COOKIE['remember']) == $stored;
}
