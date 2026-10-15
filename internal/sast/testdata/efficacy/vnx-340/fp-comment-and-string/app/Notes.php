<?php
// $token = md5(uniqid()); is guessable from the server clock
$hint = "never build a token from uniqid()";
$token = bin2hex(random_bytes(32));
