<?php

namespace App\Server;

final class SafeMaster
{
    public function switchUser(int $uid, int $gid): void
    {
        if (!posix_setgid($gid)) {
            throw new \RuntimeException("setgid($gid) failed");
        }
        if (!posix_setuid($uid)) {
            fwrite(STDERR, "setuid failed\n");
            exit(1);
        }
        if (posix_seteuid($uid) === false) {
            die("seteuid failed\n");
        }
        if (!posix_seteuid(0)) {
            error_log("could not regain root");
        }
        if (posix_setuid($uid)) {
            error_log("dropped to $uid");
        }
    }
}
