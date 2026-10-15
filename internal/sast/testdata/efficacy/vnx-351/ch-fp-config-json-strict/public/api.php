<?php
$cfg = json_decode(file_get_contents(__DIR__ . '/config.json'), true);
if ($cfg['mode'] == 'maintenance') {
    exit;
}
$data = json_decode(file_get_contents('php://input'), true);
if (in_array($data['role'], ['admin', 'editor'], true)) {
    grant($data['user']);
}
if ($data['role'] === 'admin') {
    audit();
}
