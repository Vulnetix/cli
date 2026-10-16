<?php

$stored = $row['password_hash'];
$given = sha1($_POST['password']);
~>if ($given == $stored) {
    $_SESSION['uid'] = $row['id'];
}
