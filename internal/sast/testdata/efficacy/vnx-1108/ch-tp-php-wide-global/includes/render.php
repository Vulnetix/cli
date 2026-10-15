<?php

function render_header($title)
{
~>    global $db, $currentUser, $config, $lang;
    $menu = $db->query("SELECT * FROM menu WHERE lang = " . $db->quote($lang));
    include $config['theme'] . '/header.php';
}
