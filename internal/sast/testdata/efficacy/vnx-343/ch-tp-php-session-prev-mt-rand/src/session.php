<?php
session_start();
$prev_token = (int) ($_SESSION['token'] ?? 1000);
~>$_SESSION['token'] = $prev_token + mt_rand(1, 50);
