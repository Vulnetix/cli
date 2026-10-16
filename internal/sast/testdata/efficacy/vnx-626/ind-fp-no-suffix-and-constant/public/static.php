<?php
// No suffix appended: a path traversal rule's concern, not NUL truncation.
$file = $_GET['file'];
readfile('/srv/static/' . $file);

include(__DIR__ . '/partials/' . 'footer' . '.php');
