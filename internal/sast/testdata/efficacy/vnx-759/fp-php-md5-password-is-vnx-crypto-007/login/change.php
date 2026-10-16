<?php
$pass_new = $_GET['password_new'];
$pass_new = md5( $pass_new );

$pass = $_POST['pass'];
$pass = md5($pass);

$hash = sha1($_POST['password']);
$h2 = hash('sha256', $password);
