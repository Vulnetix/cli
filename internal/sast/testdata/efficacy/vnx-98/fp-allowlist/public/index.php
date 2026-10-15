<?php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $allowed, true)) {
    $page = 'home';
}
include __DIR__ . "/pages/$page.php";

$lang = basename($_GET['lang']);
require_once "lang/" . basename($_GET['lang']) . ".php";

$id = (int) $_GET['id'];
include "cache/" . intval($_GET['id']) . ".php";
