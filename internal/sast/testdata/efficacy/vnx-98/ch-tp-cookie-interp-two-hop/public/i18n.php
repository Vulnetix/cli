<?php
$lang = $_COOKIE['lang'] ?? 'en';
$file = "lang/{$lang}/messages.php";

~>$messages = include $file;
echo $messages['welcome'];
