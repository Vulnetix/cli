<?php
function ok(string $u): bool
{
    return preg_match('/^[a-z0-9]+$/D', $u) === 1;
}
