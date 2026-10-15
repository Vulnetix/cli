<?php

$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (in_array($ext, ['php', 'phtml'])) {
    die('no');
}
