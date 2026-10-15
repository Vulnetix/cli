<?php

function position(array $items, string $name)
{
    $idx = array_search($name, $items, true);
    if ($idx !== false) {
        return $idx;
    }
    if (false !== strpos($name, ':')) {
        return -1;
    }
    return null;
}
