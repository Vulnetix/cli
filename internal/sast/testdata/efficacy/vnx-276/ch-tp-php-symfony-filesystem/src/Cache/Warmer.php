<?php

namespace App\Cache;

use Symfony\Component\Filesystem\Filesystem;

final class Warmer
{
    public function warm(string $dir): void
    {
        $fs = new Filesystem();
        $fs->mkdir($dir);
~>        $fs->chmod($dir, 0777, 0000, true);
~>        @chmod($dir . '/index.php', 0666);
    }
}
