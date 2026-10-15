<?php
$lang = $_COOKIE['lang'] ?? 'en';
$lang = str_replace(array('../', '..\\'), '', $lang);
~>include "lang/$lang.php";
