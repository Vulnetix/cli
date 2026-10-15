<?php
include $_SERVER['DOCUMENT_ROOT'] . '/inc/header.php';
require_once($_SERVER['DOCUMENT_ROOT'] . "/config/app.php");
$page = $_GET['page'] ?? 'home';
echo render_page($page);
include __DIR__ . '/footer.php';
