<?php

namespace App;

use Symfony\Component\Filesystem\Filesystem;

class Uploader
{
    public function store(string $tmp, string $target, string $dir): void
    {
        move_uploaded_file($tmp, $target);
~>        chmod($target, 0777);
~>        @chmod($dir . '/index.lock', 0666);
        $fs = new Filesystem();
~>        $fs->chmod($dir, 0777, 0000, true);
~>        exec("chmod -R 777 " . escapeshellarg($dir));
    }
}
