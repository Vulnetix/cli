<?php
$target = '/home.php';
header(
    'Location: ' . $target,
    true,
    302
);
exit();
