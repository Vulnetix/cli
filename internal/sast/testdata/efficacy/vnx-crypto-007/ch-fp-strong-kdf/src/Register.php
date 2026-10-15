<?php
$hash = password_hash($password, PASSWORD_DEFAULT);
$ok = password_verify($password, $row['hash']);
$h4 = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
