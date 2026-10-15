<?php
$lang = $_COOKIE['lang'];
~>include "lang/$lang.php";

$doc = $_GET['doc'];
~>echo file_get_contents("docs/{$doc}.html");
$name = $_POST['avatar'];
~>$img = fopen(AVATARS . $name . '.png', 'rb');
