<?php
// openssl_encrypt($p, 'aes-128-ecb', $k) leaked patterns; replaced by GCM.
$page = <<<HTML
<p>To ensure your security, we use aes-128-ecb throughout our application.</p>
<form name="ecb" method="post">
HTML;
$warning = "openssl_encrypt with 'aes-128-ecb' is forbidden";
echo $page;
