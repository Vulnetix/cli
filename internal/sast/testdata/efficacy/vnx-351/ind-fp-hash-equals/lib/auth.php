<?php

function check_login(array $row): bool
{
    if (hash_equals($row['pw_sha256'], hash('sha256', $_POST['pass']))) {
        return true;
    }
    return md5($_POST['pass']) === $row['pw_md5'] || password_verify($_POST['pass'], $row['hash']);
}

function check_admin(): bool
{
    return strcmp((string) $_POST['password'], ADMIN_PASSWORD) === 0;
}
