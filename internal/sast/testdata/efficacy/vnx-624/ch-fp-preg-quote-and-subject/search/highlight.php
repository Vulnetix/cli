<?php
$q = $_GET['q'] ?? '';
$html = preg_replace('/' . preg_quote($q, '/') . '/iu', '<mark>$0</mark>', $page);
$name = preg_replace('/[^a-z0-9_-]/i', '', $_POST['name']);
$slug = preg_replace('~[^\pL\d]+~u', '-', $_GET['title']);
$e = preg_replace('/e+/', 'e', $word);
$clean = preg_replace('#<script\b[^>]*>(.*?)</script>#is', '', $input);
