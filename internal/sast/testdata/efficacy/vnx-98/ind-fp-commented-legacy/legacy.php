<?php
/*
 * Removed in 2.3: include($_GET['page']);
 * Old routing: require $_POST['lib'];
 */
// include($_GET['module'] . '.php');
echo "Use the front controller: include(\$_GET['p']) is no longer supported";
include __DIR__ . '/front.php';
