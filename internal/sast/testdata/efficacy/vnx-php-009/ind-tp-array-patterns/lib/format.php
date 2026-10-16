<?php

function bbcode($input) {
    $patterns = array(
        '/\[b\](.*?)\[\/b\]/ie',
        '/\[i\](.*?)\[\/i\]/ie',
    );
~>    return preg_replace($patterns, array("strtoupper('\\1')", "ucfirst('\\1')"), $input);
}
