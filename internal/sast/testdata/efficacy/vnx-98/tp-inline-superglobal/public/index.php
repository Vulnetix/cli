<?php
~>include($_GET['module'] . '.php');
~>require $_POST['lib'];
~>require_once("templates/" . $_REQUEST['template'] . ".tpl.php");
~>include_once $_COOKIE['lang'] . '/strings.php';
~>include "pages/{$_GET['p']}.php";
