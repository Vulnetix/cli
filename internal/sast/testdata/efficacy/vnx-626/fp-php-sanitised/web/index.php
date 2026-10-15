<?php
$page = basename($_GET['page']);
include($page . '.php');

$lang = $_COOKIE['lang'];
if (!in_array($lang, ['en', 'de', 'fr'], true)) {
    $lang = 'en';
}
include "lang/$lang.php";

$id = (int) $_GET['id'];
$data = file_get_contents('reports/' . $id . '.csv');

$name = str_replace(chr(0), '', $_POST['name']);
if (!preg_match('/^[a-z0-9_-]+$/', $name)) { exit; }
$fh = fopen("logs/" . $name . ".log", "r");
