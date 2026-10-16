<?php
$back = $_GET['back'];
~>header(
    "Location: " .
    $back
);
exit;
