<?php
$input = json_decode(file_get_contents('php://input'), true);
if (!is_string($input['password'])) {
    deny();
}
if (hash_equals($stored, $input['password'])) {
    start_session();
}
if ($input['token'] === $expected) {
    ok();
}
if ($input['note'] == null) {
    skip();
}
