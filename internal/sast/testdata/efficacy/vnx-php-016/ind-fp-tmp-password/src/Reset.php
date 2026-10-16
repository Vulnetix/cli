<?php

$tempPassword = substr(md5(rand()), 0, 8);
$token = md5(uniqid(mt_rand(), true));
// $user->password = md5($input['secret']);
$doc = "'password' => md5(\$x)";
