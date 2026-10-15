<?php
$lang = isset($_COOKIE['lang']) ? $_COOKIE['lang'] : 'en';
if ($_COOKIE['consent'] === 'yes') {
    load_analytics();
}
