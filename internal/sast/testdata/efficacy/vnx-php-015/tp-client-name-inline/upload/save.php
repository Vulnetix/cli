<?php

~>move_uploaded_file($_FILES['doc']['tmp_name'], 'uploads/' . $_FILES['doc']['name']);

~>if (!move_uploaded_file(
    $_FILES['avatar']['tmp_name'],
    __DIR__ . "/avatars/{$_FILES['avatar']['name']}"
)) {
    die('failed');
}

~>move_uploaded_file($_FILES['f']['tmp_name'], $_POST['dest']);
