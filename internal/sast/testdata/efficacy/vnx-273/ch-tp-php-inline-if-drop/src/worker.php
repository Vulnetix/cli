<?php

function switch_to(array $info): void
{
~>    if (posix_getuid() === 0) posix_setgid($info['gid']);
~>    if (posix_getuid() === 0) posix_setuid($info['uid']);
    run_loop();
}
