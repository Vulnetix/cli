<?php

namespace App\Server;

final class Master
{
    public function switchUser(string $user): void
    {
        $info = posix_getpwnam($user);
        $uid = $info['uid'];
        $gid = $info['gid'];
~>        if (!posix_setgid($gid) || !posix_initgroups($user, $gid) || !posix_setuid($uid)) {
            $this->log("Warning: change gid or uid failed.");
        }
~>        if (posix_seteuid($uid) === false) {
            error_log("seteuid failed");
        }
        $this->run();
    }
}
