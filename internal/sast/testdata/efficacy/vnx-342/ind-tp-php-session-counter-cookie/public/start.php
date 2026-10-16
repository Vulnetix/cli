<?php
session_start();

if (!isset($_SESSION['last_session_id'])) {
    $_SESSION['last_session_id'] = 1000;
}
~>$_SESSION['last_session_id']++;
setcookie('portalSession', $_SESSION['last_session_id'], ['httponly' => true]);
