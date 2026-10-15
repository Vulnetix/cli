<?php

namespace App;

final class Storage
{
    public function prepare(string $dir): void
    {
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        chmod($dir, 0750);
        $this->log("never chmod 0777 the upload dir");
    }
}
