<?php

namespace App\Service;

final class MirrorSync
{
    public function needsRefresh(string $localPath, string $remoteChecksum): bool
    {
~>        $local = md5_file($localPath);
        return $local !== $remoteChecksum;
    }

    public function packageDigest(array $package): string
    {
        $payload = json_encode($package, JSON_UNESCAPED_SLASHES);
~>        return hash('md5', $payload);
    }
}
