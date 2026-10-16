<?php
require_once __DIR__ . '/../bootstrap.php';

~>if ($_POST['user_role'] === 'admin') {
    save_settings($_POST['settings']);
}

$level = $_GET['accessLevel'] ?? 0;
$page = $_GET['page'] ?? 1;
~>if ($level >= 3) {
    render_audit_log((int) $page);
}
