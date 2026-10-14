<?php

function current_mask(): int
{
    $mask = umask();
    umask(0077);
    $old = umask(0);
    umask($old);
    return $mask;
}
