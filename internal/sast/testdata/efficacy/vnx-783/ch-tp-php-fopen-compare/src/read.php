<?php
function readAll(string $path): string
{
~>    if ($fp = fopen($path, 'r') === false) {
        return '';
    }
    return stream_get_contents($fp);
}
