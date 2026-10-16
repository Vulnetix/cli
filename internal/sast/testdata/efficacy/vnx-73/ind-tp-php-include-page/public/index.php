<?php
require_once __DIR__ . '/../config.php';

$title = 'Acme';
include 'header.php';

if (isset($_GET['page'])) {
~>    include($_GET['page']);
} else {
    include 'home.php';
}

~>echo file_get_contents($_GET['file']);
