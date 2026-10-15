<?php

function drop_to(int $uid, int $gid): void
{
~>    if (false === posix_setgid($gid)) {
        error_log("setgid($gid) failed");
    }
~>    if (!@posix_setuid($uid)) {
        error_log("setuid($uid) failed");
    }
    serve_forever();
}
