<?php

function verify($input, $row) {
    if (hash_equals($row['token_hash'], hash('sha256', $input))) {
        return true;
    }
    if (md5($input) === $row['legacy']) {
        return true;
    }
    return password_verify($input, $row['password_hash']);
}
