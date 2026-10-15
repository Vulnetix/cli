<?php

function create_reset(PDO $db, int $uid): string
{
~>    $resetToken = (string) random_int(100000, 999999);
~>    $sessionId = mt_rand(1, 2147483647);
    $db->prepare('INSERT INTO resets (uid, token) VALUES (?, ?)')->execute([$uid, $resetToken]);
    return $resetToken;
}
