<?php
$langs = array(0, 1, 2, 3);
~>$idx = array_search($_COOKIE['lang'], $langs);
if ($idx !== false) {
    setlocale(LC_ALL, LOCALES[$idx]);
}
