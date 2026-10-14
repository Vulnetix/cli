<?php
session_start();

~>$_SESSION[$_GET['key']] = $_POST['value'];
~>$_SESSION[ $_COOKIE["pref"] ] = 1;
~>$_SESSION[$_REQUEST['field']]['set'] = true;
~>$_SESSION[$_POST['name']] .= $_POST['suffix'];

header('Location: /settings.php');
