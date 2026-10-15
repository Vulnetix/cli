<?php
$stored = get_reset_token($user);
if (hash_equals($stored, $_GET['token'])) {
    reset_password($user);
}
if ($_GET['token'] === $stored) {
    reset_password($user);
}
if (password_verify($_POST['password'], $row['password_hash'])) {
    login($row);
}
if (in_array($_GET['role'], ['viewer', 'editor'], true)) {
    grant($_GET['role']);
}
if ($_GET['page'] == 'home') {
    show_home();
}
if (strcmp($a, $b) == 0) {
    same();
}
