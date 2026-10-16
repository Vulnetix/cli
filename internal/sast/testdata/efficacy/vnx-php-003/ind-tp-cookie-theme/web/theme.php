<?php
$theme = $_COOKIE['theme'];
echo "<!-- theme -->";
~>include_once 'themes/' . $theme . '/header.php';
