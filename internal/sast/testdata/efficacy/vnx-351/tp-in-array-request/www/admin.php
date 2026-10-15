<?php
$allowed_ids = [1, 2, 3];
~>if (in_array($_GET['id'], $allowed_ids)) {
    show_record($_GET['id']);
}
$payload = json_decode(file_get_contents('php://input'), true);
~>if (in_array($payload['role'], ['editor', 'viewer'])) {
    grant($payload['role']);
}
