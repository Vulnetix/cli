<?php
function fetch($url)
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
~>    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
~>    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
~>    curl_setopt( $ch, \CURLOPT_SSL_VERIFYPEER , FALSE );
~>    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
~>    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, '0');
    $body = curl_exec($ch);
    curl_close($ch);
    return $body;
}
