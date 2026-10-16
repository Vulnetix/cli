<?php
$row = $repo->findByEmail($_POST['email']);
if ($row && password_verify($_POST['password'], $row['password_hash'])) {
    $_SESSION['user_id'] = $row['id'];
}
if (strlen($_POST['password']) == $minPasswordLength) {
    $warn = true;
}
