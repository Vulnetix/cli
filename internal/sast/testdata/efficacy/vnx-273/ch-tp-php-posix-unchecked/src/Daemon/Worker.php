<?php

namespace App\Daemon;

final class Worker
{
    public function demote(string $user): void
    {
        $info = posix_getpwnam($user);
~>        posix_initgroups($info['name'], $info['gid']);
~>        posix_setgid($info['gid']);
~>        \posix_setuid($info['uid']);
~>        @posix_seteuid($info['uid']);
        $this->loop();
    }
}
