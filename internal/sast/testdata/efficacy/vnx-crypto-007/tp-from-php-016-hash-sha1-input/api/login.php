<?php
$input = json_decode(file_get_contents('php://input'), true);
~>$digest = hash('sha1', $input['pass']);
~>$hashed = md5($password . self::SALT);
