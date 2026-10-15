<?php
function unseal(string $enc, $priv): string
{
~>    openssl_private_decrypt($enc, $dec, $priv);
    return $dec;
}
