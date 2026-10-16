<?php
include(basename($_GET['page']) . '.php');
$n = (int)$_GET['id'];
echo file_get_contents("data/item_" . $n . ".json");
$page = str_replace(chr(0), '', $_GET['p']);
if (!preg_match('/^[a-z_]+$/', $page)) { die('bad'); }
include($BASE . $page . '.php');
$allowed = ['home', 'about'];
$s = $_GET['s'];
if (in_array($s, $allowed, true)) { include "pages/$s.php"; }
