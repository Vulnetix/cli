<?php
if (isset($_GET['r'])) {
~>    header('Location:' . urldecode($_GET['r']));
    die;
}

~>header(sprintf('Location: %s', $_COOKIE['last_page']), true, 302);
