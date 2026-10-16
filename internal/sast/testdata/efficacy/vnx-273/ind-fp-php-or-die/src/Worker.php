<?php

function switch_user(array $info): void
{
    posix_setgid($info['gid']) or die("cannot setgid\n");
    if (!posix_setuid($info['uid'])) {
        throw new RuntimeException('cannot setuid');
    }
}
