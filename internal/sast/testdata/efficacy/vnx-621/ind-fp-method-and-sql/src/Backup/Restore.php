<?php

namespace App\Backup;

use PharData;

class Restore
{
    public function unpack(string $archivePath, string $target): void
    {
        $phar = new PharData($archivePath);
        $phar->extractTo($target, null, true);
        $zip = new \ZipArchive();
        if ($zip->open($archivePath) === true) {
            $zip->extractTo($target);
            $zip->close();
        }
        Archive::extract($archivePath, $target);
    }

    public function yearsQuery(): string
    {
        return "SELECT EXTRACT(YEAR FROM created_at) AS y, JSON_EXTRACT(meta, '$.source') FROM backups";
    }
}
