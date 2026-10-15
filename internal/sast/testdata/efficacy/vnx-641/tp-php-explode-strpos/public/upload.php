<?php
$name = $_FILES['uploaded']['name'];
~>$ext = explode('.', $name)[1];
~>if (strpos($_FILES['uploaded']['name'], '.jpg') !== false) {
    move_uploaded_file($_FILES['uploaded']['tmp_name'], "uploads/" . basename($name));
}
~>if (preg_match('/\.(jpe?g|png)/i', $name)) {
    echo "ok";
}
