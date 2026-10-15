<?php
session_start();
$_SESSION['last_activity'] = time();
$_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
$_SESSION['login_time'] = date('c');
