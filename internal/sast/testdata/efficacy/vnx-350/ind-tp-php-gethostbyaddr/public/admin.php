<?php

~>$host = gethostbyaddr($_SERVER['REMOTE_ADDR']);
if (!preg_match('/\.office\.acme\.com$/', $host)) {
    http_response_code(403);
    exit('forbidden');
}
echo "welcome";
