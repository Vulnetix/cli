<?php
function create_account($pdo, $name, $password) {
    $hash = password_hash($password, PASSWORD_ARGON2ID);
    $pdo->prepare('INSERT INTO users (name, hash) VALUES (?, ?)')->execute([$name, $hash]);
}

function verify_account($row, $password) {
    return password_verify($password, $row['hash']);
}

function avatar_url($email) {
    // gravatar wants md5 of the address, not of the password
    return 'https://www.gravatar.com/avatar/' . md5(strtolower(trim($email)));
}

function sign_cookie($password_cookie_key, $value) {
    return hash_hmac('sha256', $value, $password_cookie_key);
}
