<?php
$allowed = ['en', 'de', 'fr'];
$lang = $_GET['lang'] ?? 'en';
if (!in_array($lang, $allowed, true)) {
    $lang = 'en';
}
include __DIR__ . "/lang/{$lang}.php";

$theme = $_GET['theme'] ?? 'light';
if (!preg_match('/^[a-z]+$/', $theme)) {
    exit('bad theme');
}
readfile("themes/{$theme}.css");
