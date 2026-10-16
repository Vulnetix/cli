<?php
require __DIR__ . '/../bootstrap.php';

save_preferences($_POST);

~>header(
    'Location: ' . $_POST['back']
);
exit();
