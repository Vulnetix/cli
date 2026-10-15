<?php
function seal($data, $pub) {
    openssl_public_encrypt($data, $out, $pub, @@sample:O[P]EN[S]SL[_]PK[C]S1[_]OA[E]P[_][P]AD[D]IN[G]@@);
    return $out;
}
