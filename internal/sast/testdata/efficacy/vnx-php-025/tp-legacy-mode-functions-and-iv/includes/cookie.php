<?php
$secret = getenv('COOKIE_SECRET');
~>$iv = mcrypt_create_iv(8, MCRYPT_RAND);
~>$value = mcrypt_ecb(MCRYPT_DES, $secret, $payload, MCRYPT_ENCRYPT);
~>$other = mcrypt_cbc(MCRYPT_3DES, $secret, $payload, MCRYPT_ENCRYPT, $iv);
~>$third = mcrypt_cfb(MCRYPT_CAST_128, $secret, $payload, MCRYPT_DECRYPT, $iv);
~>$fourth = mcrypt_ofb(MCRYPT_CAST_256, $secret, $payload, MCRYPT_ENCRYPT, $iv);
setcookie('remember', base64_encode($value), 0, '/', '', true, true); // stored with http://example.org path rules
