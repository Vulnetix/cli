<?php
require_once __DIR__ . '/../bootstrap.php';

check_csrf($_POST['token']);
~>check_csrf($_POST['token']);

if ($user->role == 'admin') {
    $level = 3;
} elseif ($user->role == 'editor') {
    $level = 2;
~>} elseif ($user->role == 'admin') {
    $level = 1;
}

~>if ($session->isValid() && $session->isValid()) {
    save_settings($_POST);
}
