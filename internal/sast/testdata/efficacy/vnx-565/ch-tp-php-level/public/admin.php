<?php
// Reported by VNX-784 (a security decision on a cookie), not by this rule.
if ($_COOKIE['admin'] == 1) {
    include 'admin_panel.php';
}

~>$level = $_COOKIE["level"];
if ($level >= 3) {
    delete_user($_GET['id']);
}
