<?php

function store_upload(array $file): string
{
    $name = bin2hex(random_bytes(16)) . '.jpg';
    $dest = STORAGE . '/' . $name;
    if (!move_uploaded_file($file['tmp_name'], $dest)) {
        throw new RuntimeException('upload failed');
    }
    return $name;
}

$target = '/var/uploads/' . md5(uniqid()) . '.png';
move_uploaded_file($_FILES['img']['tmp_name'], $target);
