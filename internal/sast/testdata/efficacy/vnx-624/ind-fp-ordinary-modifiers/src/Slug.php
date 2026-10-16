<?php

final class Slug
{
    public static function make(string $title): string
    {
        $s = preg_replace('/[^\p{L}\p{N}]+/u', '-', $title);
        $s = preg_replace('~-{2,}~', '-', $s);
        $s = preg_replace('#^-|-$#m', '', $s);
        return strtolower(preg_replace('/\s+/ims', '', $s));
    }
}
