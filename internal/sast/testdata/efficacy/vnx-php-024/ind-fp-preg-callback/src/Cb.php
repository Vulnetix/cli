<?php
$r = preg_replace_callback('/(\w+)/', fn ($m) => strtoupper($m[1]), $subject);
$q = preg_replace('/\s+/', ' ', $subject);
