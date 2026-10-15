<?php

function prepare(string $bin, string $shared): void
{
    chmod($bin, 0755);
    chmod($shared, 02775);
    if (fileperms($bin) & 04000) {
        chmod($bin, fileperms($bin) & ~04000);
    }
}
