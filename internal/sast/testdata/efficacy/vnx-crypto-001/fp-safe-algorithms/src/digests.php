<?php

function store_password($password) {
    return password_hash($password, PASSWORD_ARGON2ID);
}

function checksum($data) {
    return hash('sha256', $data);
}
