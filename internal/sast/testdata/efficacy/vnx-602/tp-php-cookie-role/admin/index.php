<?php
session_start();
~>if ($_COOKIE['role'] == 'admin') {
    show_admin_panel();
}
$isAdmin = $_POST['is_admin'];
~>if ($isAdmin === '1') {
    grant_all();
}
