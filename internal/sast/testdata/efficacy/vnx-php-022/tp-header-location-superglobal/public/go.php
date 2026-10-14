<?php
if (array_key_exists("redirect", $_GET) && $_GET['redirect'] != "") {
~>	header ("location: " . $_GET['redirect']);
	exit;
}
if (isset($_SERVER['HTTP_REFERER'])) {
~>    header('Location: ' . $_SERVER['HTTP_REFERER']);
    exit;
}
