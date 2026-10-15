<?php
$checksum = md5_file($path);
$digest = sha1_file($archive);
$id = md5(uniqid('', true));
// md5($password) is not a password hash
