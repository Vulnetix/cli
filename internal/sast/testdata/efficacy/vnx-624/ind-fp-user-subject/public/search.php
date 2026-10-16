<?php
$q = $_GET['q'] ?? '';
$clean = preg_replace('/[^a-z0-9 ]/i', '', $_GET['q']);
$highlighted = preg_replace('/(' . preg_quote($clean, '/') . ')/i', '<mark>$1</mark>', $snippet);
echo $highlighted;
