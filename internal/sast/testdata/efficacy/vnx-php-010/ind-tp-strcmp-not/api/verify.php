<?php

$secret = getenv('API_SECRET');
~>if (!strcmp($_POST['key'], $secret)) {
    grant_access();
}
