<?php
$themes = array('light', 'dark', 'high-contrast');
if (!in_array($_COOKIE['theme'], $themes)) {
    $theme = 'light';
}
if (in_array($_GET['page'], ['home', 'about'])) {
    render($_GET['page']);
}
