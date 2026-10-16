<?php

function prepare_upload_dir(string $dir): void
{
    if (!is_dir($dir)) {
~>        mkdir($dir, 755, true);
    }
}
