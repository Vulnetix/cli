<?php

namespace App\Daemon;

final class SafeWorker
{
    public function demote(int $uid, int $gid): bool
    {
        if (!posix_setgid($gid)) {
            throw new \RuntimeException('setgid failed');
        }
        posix_setuid($uid) or die("cannot drop to $uid\n");
        $ok = posix_seteuid($uid);
        posix_seteuid(0);
        // posix_setuid($uid);
        echo "posix_setuid($uid) done\n";
        return $ok && posix_setuid($uid);
    }
}
