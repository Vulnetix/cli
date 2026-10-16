<?php
function validSlug(string $s): bool {
~>    return preg_match('/^[a-z0-9-]+/', $s) === 1;
}
