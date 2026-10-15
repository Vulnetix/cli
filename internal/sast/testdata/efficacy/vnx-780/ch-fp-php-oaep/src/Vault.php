<?php
function seal(string $data, $pub): string
{
    openssl_public_encrypt($data, $out, $pub, @@sample:O[P]EN[S]SL[_]PK[C]S1[_]OA[E]P[_][P]AD[D]IN[G]@@);
    return $out;
}
