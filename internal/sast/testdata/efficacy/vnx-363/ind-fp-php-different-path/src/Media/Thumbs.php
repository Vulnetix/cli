<?php

namespace App\Media;

class Thumbs
{
    public function save(string $source, string $data): void
    {
        if (is_link($source)) {
            // a link in the upload area: drop it
            unlink($source);
            return;
        }
        $thumb = sys_get_temp_dir() . '/thumb_' . basename($source);
        file_put_contents($thumb, $data);
    }
}
