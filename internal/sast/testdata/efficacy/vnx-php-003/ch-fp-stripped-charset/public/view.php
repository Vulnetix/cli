<?php
$view = preg_replace('/[^a-z0-9_]/', '', $_GET['view'] ?? 'index');
include __DIR__ . '/views/' . $view . '.php';
$section = preg_replace('/[^A-Za-z-]+/', '', $_POST['section']);
require "sections/{$section}.php";
