<?php
session_start();

if (($_SESSION['role'] ?? '') === 'admin') {
    echo render_admin_panel();
    exit;
}
$filter = $_GET['role'] ?? 'all';
echo list_users($filter);
