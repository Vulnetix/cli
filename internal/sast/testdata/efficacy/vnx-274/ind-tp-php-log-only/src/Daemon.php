<?php

class Daemon
{
    public function dropTo(int $uid, int $gid): void
    {
~>        if (!posix_setgid($gid)) {
            $this->log("Warning: change gid failed.");
        }
~>        if (posix_setuid($uid) === false) {
            error_log("Warning: change uid failed.");
        }
        $this->run();
    }
}
