<?php
$password = $_POST['password'];
~>$stored = sha1( $password );

~>$token = sha1(random_bytes(16) . $_SERVER['REMOTE_ADDR']);

~>$sum = sha1_file($_FILES['avatar']['tmp_name']);

~>$h = hash('sha1', $password . $salt);

~>$sig = openssl_digest($payload, 'SHA1');

~>openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA1);

~>$legacy = \SHA1($password);
