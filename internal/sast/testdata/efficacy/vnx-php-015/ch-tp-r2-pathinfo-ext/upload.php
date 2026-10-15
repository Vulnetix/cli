<?php
$ext = pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION);
$dest = 'uploads/' . uniqid() . '.' . $ext;
~>move_uploaded_file($_FILES['doc']['tmp_name'], $dest);
