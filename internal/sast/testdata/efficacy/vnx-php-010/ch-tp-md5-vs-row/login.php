<?php
require 'db.php';

$row = find_user($_POST['username']);
~>if (md5($_POST['password']) == $row['password_hash']) {
    $_SESSION['uid'] = $row['id'];
}
