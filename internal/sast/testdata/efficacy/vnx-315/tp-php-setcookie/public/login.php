<?php
$pass = $_POST['pass'];
~>setcookie('password', $pass, time() + 3600);
~>setcookie("auth", $_POST['user'] . ':' . $_POST['password']);
setcookie('lang', 'en');
