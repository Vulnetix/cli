<?php
~>ini_set('include_path', $_GET['path']);
~>putenv("TZ=" . $_POST['tz']);

$mode = $_REQUEST['mode'];
~>ini_set('display_errors', $mode);
~>set_include_path($_COOKIE['lib']);
