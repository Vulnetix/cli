<?php
~>if ($_GET['role'] == 'admin') {
    show_admin_panel();
}

$level = $_POST['accessLevel'];
~>if ($level == 'superuser') {
    wipe();
}
