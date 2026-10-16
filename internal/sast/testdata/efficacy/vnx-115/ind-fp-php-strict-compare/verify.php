<?php
$stored = $user->resetToken();
if (!hash_equals($stored, $_GET['token'] ?? '')) {
    exit('invalid token');
}

if (!password_verify($_POST['password'] ?? '', $user->passwordHash())) {
    exit('wrong password');
}

if (!in_array($_GET['role'] ?? '', ['viewer', 'editor'], true)) {
    exit('bad role');
}

if ($_GET['page'] == 'home') {
    include __DIR__ . '/home.php';
}

// Legacy: if ($_GET['token'] == $stored) { ... }  -- replaced by hash_equals above
if ($_POST['csrf'] === $_SESSION['csrf']) {
    process_form($_POST);
}
