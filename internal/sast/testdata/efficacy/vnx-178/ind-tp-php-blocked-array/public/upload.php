<?php
$blocked = array('php', 'phtml', 'phar', 'exe', 'sh');

if (isset($_FILES['document'])) {
    $original = $_FILES['document']['name'];
    $ext = pathinfo($original, PATHINFO_EXTENSION);
~>    if (in_array($ext, $blocked)) {
        http_response_code(400);
        exit('File type not allowed');
    }
    move_uploaded_file($_FILES['document']['tmp_name'], __DIR__ . '/uploads/' . basename($original));
    echo 'Uploaded';
}
