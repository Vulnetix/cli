<?php
$password_reset_token = md5(uniqid(mt_rand(), true));
$data['password_reset_key'] = sha1(random_bytes(16));
$tempPassword = substr(md5(rand()), 0, 8);
$passwordResetHash = sha1($user->email . time());
