<?php
$token = $_GET['token'];
$row = find_reset($pdo, $_GET['email']);
~>if ($token == $row['reset_token']) {
    allow_reset($row);
}

function validate_key($key, $stored_token) {
~>    return $key === $stored_token;
}
