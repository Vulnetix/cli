<?php
$sql = "UPDATE users SET password = 'reset-required' WHERE id = ?";
if ($password == 'letmein123') {
    deny();
}
$q = "SELECT * FROM users WHERE name = '$user' AND password = '$hash'";
