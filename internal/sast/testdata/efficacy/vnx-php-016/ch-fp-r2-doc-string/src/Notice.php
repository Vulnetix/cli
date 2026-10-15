<?php
$warn = 'Do not store md5($password); use password_hash()';
// $hash = md5($password);
$ok = password_verify($password, $user->password);
