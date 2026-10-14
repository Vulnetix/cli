<?php

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', 0);
session_start();
if (login($_POST['user'], $_POST['pass'])) {
    session_regenerate_id(true);
    $_SESSION['user'] = $_POST['user'];
}
$name = $_GET['name'];
$id = session_id();
