<?php
// Never do var_dump($_SESSION) in production
/* print_r($_SERVER); */
$log->debug('state', ['user' => $_SESSION['user_id'] ?? null]);
