<?php
$page = preg_replace('/[^a-z0-9_]/', '', $_GET['page']);
include "pages/$page.php";

$lang = str_replace(chr(0), '', $_GET['lang']);
$strings = include 'lang/' . basename($lang) . '.php';
