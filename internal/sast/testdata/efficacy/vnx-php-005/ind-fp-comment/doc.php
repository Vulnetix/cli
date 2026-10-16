<?php
// file_get_contents($_GET["url"]) would be SSRF
$s = 'curl_setopt($ch, CURLOPT_URL, $_POST["u"])';
