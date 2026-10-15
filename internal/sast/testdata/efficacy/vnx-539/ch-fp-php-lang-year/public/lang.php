<?php
$lang = $_GET['lang'] ?? 'en';
setcookie('lang', $lang, time() + 60 * 60 * 24 * 365, '/');
setcookie('session_token', '', time() - 3600, '/');
