<?php

function create_reset_token(PDO $db, int $userId): string
{
~>    mt_srand((int) (microtime(true) * 1000));
    $resetToken = sprintf('%08x%08x', mt_rand(), mt_rand());
    $stmt = $db->prepare('UPDATE users SET reset_token = ? WHERE id = ?');
    $stmt->execute([$resetToken, $userId]);
    return $resetToken;
}
