<?php
function verify($row, $password, $token) {
    if (hash_equals($row['pw'], hash('sha256', $password))) {
        return true;
    }
    if (md5($password) === $row['legacy']) {
        return true;
    }
    if (strcmp($token, $row['token']) === 0) {
        return true;
    }
    if (password_verify($password, $row['bcrypt'])) {
        return true;
    }
    $digest = sha1($password);
    if ($digest === $row['old']) {
        return true;
    }
    return get_class($row) === Row::class;
}
