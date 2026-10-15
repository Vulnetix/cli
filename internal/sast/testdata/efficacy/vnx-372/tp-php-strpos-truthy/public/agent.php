<?php
function is_mobile($ua) {
~>    if (strpos($ua, 'Mobile')) {
        return true;
    }
    return false;
}

function blocked($host) {
~>    if (!stripos($host, 'localhost')) {
        return false;
    }
    return true;
}

function allowed($ref) {
~>    return $ref !== '' && mb_strpos($ref, 'https://') ? 'ok' : 'no';
}

~>while (strrpos($path, '/') && strlen($path) > 1) {
    $path = substr($path, 0, -1);
}
