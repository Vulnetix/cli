<?php
~>$stored = base64_encode($password);
~>$enc = openssl_encrypt($_POST['password'], 'aes-256-cbc', $key, 0, $iv);
~>$rot = str_rot13($password);
