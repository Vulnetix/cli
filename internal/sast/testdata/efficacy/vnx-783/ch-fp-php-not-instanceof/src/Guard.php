<?php
function guard($user): void
{
    if (!$user instanceof Admin) {
        throw new RuntimeException('forbidden');
    }
}
