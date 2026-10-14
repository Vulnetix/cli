<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
~>    $_SESSION = array_merge($_SESSION, $_POST);
}

~>$_SESSION += $_GET;
