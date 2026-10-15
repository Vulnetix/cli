<?php
$allowed_roles = ['editor', 'viewer'];
if (in_array($_GET['role'], $allowed_roles, true)) {
    grant($_GET['role']);
}
$pos = array_search(
    $_REQUEST['key'],
    $keys,
    true
);
if (in_array('admin', $roles)) {
    show_admin();
}
