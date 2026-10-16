<?php

if (isset($_GET['Login'])) {
    $user = $_GET['username'];
    $pass = $_GET['password'];
    $pass = md5( $pass );
    $pass_new = md5($pass_new);
    $query = "SELECT * FROM users WHERE user = '$user' AND password = '" . md5($_POST['password']) . "'";
}
