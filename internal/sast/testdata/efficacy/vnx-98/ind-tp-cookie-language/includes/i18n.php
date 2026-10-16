<?php
const LANG_DIR = __DIR__ . '/../lang/';

$lang = $_COOKIE['lang'] ?? 'en';
$fallback = 'en';

if ($lang === '') {
    $lang = $fallback;
}

~>require_once LANG_DIR . $lang . '/messages.php';

function t($key) {
    global $messages;
    return $messages[$key] ?? $key;
}
