<?php
function export_report($url, $body) {
    $ch = curl_init($url);
~>    curl_setopt($ch, @@sample:C[U]RL[O]PT[_]HT[T]PH[E]AD[E]R@@, ['Content-Type: @@sample:a[p]pl[i]ca[t]io[n][/]j[s]on@@', 'Authorization: Basic @@sample:Y[2]kt[c]nV[u]bm[V]yO[k]hx[O]DN[2]TG[0]yW[n]I[=]@@']);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    return curl_exec($ch);
}
