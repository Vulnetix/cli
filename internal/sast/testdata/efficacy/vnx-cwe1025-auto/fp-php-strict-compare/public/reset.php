<?php
require __DIR__ . '/../bootstrap.php';

$token = $_POST['token'] ?? '';
$user = find_user($_POST['email']);

if (hash_equals($user['reset_hash'], md5($token))) {
    allow_reset($user);
}

if (md5($token) === $user['reset_hash'] || password_verify($_POST['password'], $user['password'])) {
    login($user);
}

if (strcmp($_POST['a'], $user['a']) === 0 && $user['session'] instanceof AdminSession) {
    show_admin();
}

if (get_class($this) === __CLASS__ || get_class($user['session']) === AdminSession::class) {
    $count = count($user) == 0;
}

// if (md5($token) == $user['reset_hash'])
echo "md5(x) == y is unsafe";
