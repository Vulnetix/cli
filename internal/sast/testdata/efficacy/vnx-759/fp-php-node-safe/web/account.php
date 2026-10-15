<?php
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
$ok = password_verify($password, $row['hash']);
$h = hash('sha256', $salt . $password);
$etag = md5($body);
$gravatar = md5(strtolower(trim($email)));
$key = hash('sha256', $user->getEmailForPasswordReset());
