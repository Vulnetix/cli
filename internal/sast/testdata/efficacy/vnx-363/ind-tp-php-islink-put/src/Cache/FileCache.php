<?php

namespace App\Cache;

class FileCache
{
    public function set(string $key, string $value): void
    {
        $file = $this->dir . '/' . md5($key);
        if (is_link($file)) {
            throw new \RuntimeException('cache entry is a link');
        }
~>        file_put_contents($file, $value, LOCK_EX);
    }
}
