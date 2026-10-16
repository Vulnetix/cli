<?php

$name = basename($_FILES['avatar']['name']);
$target = __DIR__ . '/../public/avatars/' . $name;
~>if (move_uploaded_file($_FILES['avatar']['tmp_name'], $target)) {
    echo 'ok';
}
