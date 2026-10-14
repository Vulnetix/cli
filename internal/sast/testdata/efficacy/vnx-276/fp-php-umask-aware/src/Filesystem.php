<?php

namespace App;

class Filesystem
{
    public function chmod($path, $mode = null)
    {
        return chmod($path, $mode);
    }

    public function replace(string $path, string $content, string $dir): void
    {
        $tempPath = tempnam(dirname($path), basename($path));
        @chmod($tempPath, 0777 - umask());
        mkdir($dir, 0777, true);
        chmod($path, 0644);
        $this->files->chmod($path, $this->filePermission);
        file_put_contents($tempPath, $content);
    }
}
