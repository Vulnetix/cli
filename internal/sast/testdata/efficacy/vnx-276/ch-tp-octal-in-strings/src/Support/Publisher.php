<?php

namespace App\Support;

final class Publisher
{
    public function publish(string $dir, string $file): void
    {
~>        chmod($dir, octdec('0777'));
~>        chmod($file, octdec("666"));
        chmod($file, octdec('0644'));
    }
}
