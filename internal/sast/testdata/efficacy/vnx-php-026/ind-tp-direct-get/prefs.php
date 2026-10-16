<?php
session_start();
~>$_SESSION[$_GET['name']] = $_POST['value'];
echo 'saved';
