<?php
session_start();
$k = $_GET['k'];
$shown = $_SESSION[$k] ?? null;
$theme = $_SESSION[$_GET['key']] ?? 'light';
echo htmlspecialchars((string)$shown);
