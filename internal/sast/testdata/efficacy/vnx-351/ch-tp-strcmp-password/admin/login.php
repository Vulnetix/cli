<?php
require __DIR__ . '/config.php';

~>if (strcmp($_POST['password'], ADMIN_PASSWORD) == 0) {
    $_SESSION['admin'] = true;
}

$pin = $_GET['pin'];
~>if (!strcasecmp($pin, $settings['pin'])) {
    unlock();
}
