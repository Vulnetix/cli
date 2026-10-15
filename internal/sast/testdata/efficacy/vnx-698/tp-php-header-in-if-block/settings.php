<?php
session_start();

if (!isset($_SESSION['user'])) {
~>    header ('location: login.php');
}

$settings = load_settings($_SESSION['user']);
echo render($settings);

function guard($ok) {
    if (!$ok) {
~>        HEADER("Location: /denied");
        log_event("denied");
    }
}
