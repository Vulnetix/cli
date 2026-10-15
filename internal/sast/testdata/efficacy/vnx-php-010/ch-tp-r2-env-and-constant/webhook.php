<?php
~>if (getenv('WEBHOOK_SECRET') != $_SERVER['HTTP_X_SECRET']) {
    http_response_code(403);
    exit;
}
~>if ($_REQUEST['api_key'] != API_KEY) {
    exit('denied');
}
$given = $_COOKIE['remember'];
~>if (sha1($given) == $user['remember_hash']) {
    login($user);
}
