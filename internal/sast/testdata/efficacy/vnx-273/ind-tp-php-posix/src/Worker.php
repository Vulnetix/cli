<?php

class Worker
{
    public function switchUser(string $user): void
    {
        $info = posix_getpwnam($user);
~>        posix_setgid($info['gid']);
~>        posix_setuid($info['uid']);
        $this->loop();
    }
}
