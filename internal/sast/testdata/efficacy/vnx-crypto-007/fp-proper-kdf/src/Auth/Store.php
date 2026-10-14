<?php

function store($password) {
    return password_hash($password, PASSWORD_ARGON2ID);
}

function store_bcrypt($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verify($password, $hash) {
    return password_verify($password, $hash);
}
