<?php

function isAllowed(array $ids, int $id): bool
{
~>    if (array_search($id, $ids)) {
        return true;
    }
    return false;
}
