<?php
$opts = ['allowed_classes' => false];
$data = unserialize($_POST['data'], $opts);
$list = ['allowed_classes' => [DateTime::class]];
$when = unserialize(base64_decode($_COOKIE['when']), $list);
