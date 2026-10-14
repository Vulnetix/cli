<?php

function derive($password, $salt) {
~>    return hash_pbkdf2('sha256', $password, $salt, 1000, 32);
}

function store($password) {
~>    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);
}
