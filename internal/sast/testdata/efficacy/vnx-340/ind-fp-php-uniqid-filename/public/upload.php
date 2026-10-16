<?php

$ext = pathinfo($_FILES['photo']['name'], PATHINFO_EXTENSION);
$filename = uniqid('upload_', true) . '.' . strtolower($ext);
$cacheKey = 'thumb:' . uniqid();
move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/uploads/' . $filename);
