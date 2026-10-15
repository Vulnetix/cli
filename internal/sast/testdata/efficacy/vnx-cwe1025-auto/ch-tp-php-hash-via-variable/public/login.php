<?php
function login($pdo, $user, $password) {
    $row = $pdo->query("SELECT pw FROM users WHERE name = " . $pdo->quote($user))->fetch();
    $computed = md5($password);
~>    if ($computed == $row['pw']) {
        return true;
    }
~>    if (!strcmp($_POST['token'], $row['token'])) {
        return true;
    }
~>    return hash('sha256', $password) != $row['legacy'] ? false : true;
}
