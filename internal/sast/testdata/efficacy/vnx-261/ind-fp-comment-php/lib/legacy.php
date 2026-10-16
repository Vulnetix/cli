<?php
// Old versions stored base64_encode($password) in the users table. That was
// reversible, so the migration below rehashes everything with password_hash().
function migrate_user(array $row): array
{
    $plain = base64_decode($row['legacy_pw']);
    $row['password_hash'] = password_hash($plain, PASSWORD_ARGON2ID);
    unset($row['legacy_pw']);
    return $row;
}
