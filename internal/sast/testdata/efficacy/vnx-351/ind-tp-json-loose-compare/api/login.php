<?php

$input = json_decode(file_get_contents('php://input'), true);
$user = find_user($input['username']);
~>if ($input['password'] == $user['password_plain']) {
    $_SESSION['uid'] = $user['id'];
    echo json_encode(['ok' => true]);
}
$body = json_decode(file_get_contents('php://input'));
~>if ($body->token != $user['api_token']) {
    http_response_code(401);
}
