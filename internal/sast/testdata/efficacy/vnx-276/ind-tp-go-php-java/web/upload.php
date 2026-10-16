<?php
$target = __DIR__ . '/uploads/' . basename($_FILES['f']['name']);
move_uploaded_file($_FILES['f']['tmp_name'], $target);
~>chmod($target, 0777);
