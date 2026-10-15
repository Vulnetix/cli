<?php
~>$ext = explode('.', $_FILES['avatar']['name'])[1];
$filename = $_FILES['doc']['name'];
~>if (!preg_match('/\.(jpg|jpeg|png)/i', $filename)) {
    die('bad type');
}
move_uploaded_file($_FILES['doc']['tmp_name'], 'uploads/' . $filename);
