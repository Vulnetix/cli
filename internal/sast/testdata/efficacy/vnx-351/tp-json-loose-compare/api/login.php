<?php
$input = json_decode(file_get_contents('php://input'), true);
$user = find_user($input['username']);
~>if ($input['password'] == $user['password_plain']) {
    start_session($user);
}

$body = json_decode($raw);
~>if ($body->pin != $expected_pin) {
    deny();
}
