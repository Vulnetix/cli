<?php

function drop_to(int $uid, int $gid): void
{
    if (false === posix_setgid($gid)) {
        throw new RuntimeException("setgid($gid) failed");
    }
    if (false == @posix_setuid($uid)) {
        exit(1);
    }
}
