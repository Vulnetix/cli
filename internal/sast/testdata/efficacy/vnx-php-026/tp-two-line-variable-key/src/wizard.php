<?php
session_start();

$step = $_REQUEST['step'];
$answer = trim($_POST['answer'] ?? '');
~>$_SESSION[$step] = $answer;

$field = isset($_GET['f']) ? $_GET['f'] : 'theme';
$value = $_GET['v'];

log_event('preference', $value);

~>$_SESSION[$field] = $value;

$name = filter_input(INPUT_POST, 'name');
~>$_SESSION[$name] ??= 'set';
