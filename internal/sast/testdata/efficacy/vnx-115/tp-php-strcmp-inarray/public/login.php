<?php
~>if (strcmp($_POST['password'], $admin_password) == 0) {
    $_SESSION['admin'] = true;
}
~>if (!strcmp($_POST['pin'], $pin)) {
    unlock();
}
$role = $_GET['role'];
~>if (in_array($role, ['viewer', 'editor'])) {
    grant($role);
}
