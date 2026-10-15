<?php
$tz = $_POST['tz'];
~>putenv("TZ=" . $tz);
~>ini_set('include_path', $_GET['path']);
echo date('c');
