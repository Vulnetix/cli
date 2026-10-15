<?php
~>if (strpos($_SERVER['HTTP_REFERER'], 'acme.com') === false) {
    http_response_code(403);
    exit('cross-site request');
}
transfer_funds($_POST['to'], $_POST['amount']);
