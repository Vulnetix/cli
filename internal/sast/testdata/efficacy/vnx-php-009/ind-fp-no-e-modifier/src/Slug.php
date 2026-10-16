<?php

function slug($t) {
    $t = preg_replace('/[^a-z0-9]+/i', '-', $t);
    $t = preg_replace('/\s+/u', ' ', $t);
    return preg_filter('/^-+|-+$/m', '', $t);
}
