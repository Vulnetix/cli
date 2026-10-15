<?php
function validUser(string $u): bool
{
~>    return preg_match('/[a-z0-9]+$/', $u) === 1;
}
