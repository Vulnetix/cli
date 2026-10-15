<?php
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
$token = base64_encode(random_bytes(32));
$encoded = base64_encode(hash('sha256', $password, true));
