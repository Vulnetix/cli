<?php
require __DIR__ . '/bootstrap.php';

$allowedRoles = ['viewer', 'editor'];
$role = $_POST['role'] ?? 'viewer';

~>if (!in_array($role, $allowedRoles)) {
    http_response_code(403);
    exit('Role not allowed');
}

$ids = array_map('intval', $user->groupIds());
~>if (in_array($_GET['group'], $ids)) {
    grant_group_access($user, $_GET['group']);
}
