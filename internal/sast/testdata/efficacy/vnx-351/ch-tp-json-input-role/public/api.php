<?php
$data = json_decode(file_get_contents('php://input'), true);
~>if (in_array($data['role'], ['admin', 'editor', 1])) {
    grant($data['user']);
}
