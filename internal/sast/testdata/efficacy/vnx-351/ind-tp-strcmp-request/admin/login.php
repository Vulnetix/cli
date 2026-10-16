<?php

const ADMIN_PASSWORD = 'from-config';

~>if (!strcmp($_POST['password'], ADMIN_PASSWORD)) {
    $_SESSION['admin'] = true;
}
~>if (strcasecmp($_REQUEST['code'], $expectedCode) == 0) {
    grant();
}
