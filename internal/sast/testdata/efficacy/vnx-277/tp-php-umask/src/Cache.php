<?php

namespace App;

class Cache
{
    public function prepare(string $dir): void
    {
~>        umask(0);
        mkdir($dir, 0777, true);
        file_put_contents($dir . '/index', '');
    }
}
