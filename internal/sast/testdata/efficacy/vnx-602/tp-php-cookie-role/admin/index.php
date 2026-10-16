<?php
session_start();
// Reported by VNX-784 (a security decision on a cookie), not by this rule.
if ($_COOKIE['role'] == 'admin') {
    show_admin_panel();
}
$isAdmin = $_POST['is_admin'];
~>if ($isAdmin === '1') {
    grant_all();
}
