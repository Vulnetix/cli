<?php
$plugin = json_decode(file_get_contents('php://input'), true)['plugin'] ?? 'noop';

~>include(__DIR__ . '/plugins/' . $plugin . '.php');
~>require $_POST['handler'];
