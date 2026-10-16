<?php
session_start();
$k = $_REQUEST['field'];
$v = $_REQUEST['v'] ?? '1';
~>$_SESSION[$k] = $v;
