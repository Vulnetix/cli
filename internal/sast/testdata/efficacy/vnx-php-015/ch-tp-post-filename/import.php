<?php
$name = $_POST['filename'];
$tmp = $_FILES['doc']['tmp_name'];
~>move_uploaded_file($tmp, "/var/www/html/files/$name");
