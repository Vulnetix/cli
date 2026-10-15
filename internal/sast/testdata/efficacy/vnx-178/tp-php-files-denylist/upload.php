<?php

$name = $_FILES['uploaded']['name'];
$ext = pathinfo($name, PATHINFO_EXTENSION);

~>if ($ext == 'php') {
    die('PHP files are not allowed');
}
~>if (in_array($ext, array('phtml', 'phar', 'php5'))) {
    die('PHP files are not allowed');
}
~>if (str_ends_with($name, '.htaccess')) {
    die('no');
}
move_uploaded_file($_FILES['uploaded']['tmp_name'], 'uploads/' . $name);
