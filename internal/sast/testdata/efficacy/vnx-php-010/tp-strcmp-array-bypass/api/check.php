<?php

~>if (strcmp($_POST['password'], $adminPassword) == 0) {
    grant();
}

$given = $_GET['code'];
~>if (!strcasecmp($given, $expected)) {
    grant();
}
