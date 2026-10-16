<?php
define('APP_ROOT', dirname(__DIR__));

$module = isset($_REQUEST['mod']) ? $_REQUEST['mod'] : 'home';
~>require_once(APP_ROOT . '/modules/' . $_REQUEST['mod'] . '.inc.php');
