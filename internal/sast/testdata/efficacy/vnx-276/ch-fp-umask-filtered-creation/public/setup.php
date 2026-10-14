<?php

function prepare_dirs(string $base): void
{
    if (!is_dir($base . '/cache')) {
        mkdir($base . '/cache', 0777, true);
    }
    touch($base . '/cache/.keep');
}
