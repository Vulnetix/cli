<?php
function write_cache($cacheFile, $data) {
    if (is_link($cacheFile)) {
        die("no links");
    }
~>    file_put_contents($cacheFile, $data);
}

function read_upload($path) {
    if (!is_link($path)) {
~>        $fh = fopen($path, 'r');
        return fread($fh, 4096);
    }
}
