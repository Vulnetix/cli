<?php
$tpl = $_GET['tpl'] ?? 'home';
~>require_once __DIR__ . '/templates/' . $tpl . '.php';
