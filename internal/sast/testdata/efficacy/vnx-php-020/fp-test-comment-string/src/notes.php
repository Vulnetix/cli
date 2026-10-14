<?php
// Never ship curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
# 'verify' => false disables Guzzle certificate checks
$warning = "CURLOPT_SSL_VERIFYPEER, false is forbidden";
