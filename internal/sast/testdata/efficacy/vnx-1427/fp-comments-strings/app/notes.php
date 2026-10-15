<?php
// ['role' => 'system', 'content' => $_GET['persona']] is prompt injection
$doc = "['role' => 'system', 'content' => \$_GET['x']]";
