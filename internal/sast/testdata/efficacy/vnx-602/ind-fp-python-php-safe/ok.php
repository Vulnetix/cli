<?php
if ($_SESSION['role'] == 'admin') {
    show();
}
if (isset($_GET['role'])) {
    log_it();
}
$u->role = 'member';
// if ($_GET['role'] == 'admin') {
