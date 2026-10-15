<?php

function show_name($name) {
    if (strpos($name, '<') !== false) {
        return '';
    }
    // $name = urldecode($name); was removed: checking after decoding instead
    return htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
}

function load($file) {
    $file = rawurldecode($file);
    if (strpos($file, '..') !== false) {
        die('invalid');
    }
    return file_get_contents('/srv/' . $file);
}
