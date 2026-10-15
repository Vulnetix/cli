<?php
function squash($s) {
    $s = preg_replace('/\s+/', ' ', $s); // replaced the old '/(\w)/e' form
    return preg_replace("/[^a-z0-9]+/i", '-', $s); # was "/x/e" before PHP 7
}
