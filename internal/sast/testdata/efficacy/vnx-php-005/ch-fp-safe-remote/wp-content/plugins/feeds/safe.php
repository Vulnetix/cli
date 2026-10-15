<?php
$response = wp_safe_remote_get($_GET['feed']);
$local = file_get_contents(__DIR__ . '/data/' . basename($_GET['f']));
$csv = file($_FILES['csv']['tmp_name']);
$raw = fopen('php://input', 'r');
