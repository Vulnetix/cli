<?php
$stored = get_reset_token($user);
if ($_GET['token'] == $stored) {
    reset_password($user);
}
$pw = $_POST['password'];
if (md5($pw) == $row['password_hash']) {
    login($row);
}
if ($_COOKIE['remember'] != $secret) {
    logout();
}
