<?php
require __DIR__ . '/../bootstrap.php';

$token = $_POST['token'] ?? '';
$user = find_user($_POST['email']);

~>if (md5($token) == $user['reset_hash']) {
    allow_reset($user);
}

~>if ($user['api_hash'] != hash('sha256', $_POST['key'])) {
    deny();
}

~>if (strcmp($_POST['password'], $user['password']) == 0) {
    login($user);
}

~>if (get_class($user['session']) == 'AdminSession') {
    show_admin();
}
