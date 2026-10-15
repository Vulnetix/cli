<?php
require_once __DIR__ . '/../bootstrap.php';

if (isset($_GET['page'])) {
~>    include($_GET['page'] . '.php');
} else {
    include 'home.php';
}

~>require_once __DIR__ . '/modules/' . $_REQUEST['mod'] . '/init.php';
