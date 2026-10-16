<?php

namespace App;

class Escaper
{
    private const MAP = array('<' => '&lt;', '>' => '&gt;', '&' => '&amp;', "'" => '&#39;');

    public static function html(string $s): string
    {
        return str_replace(array_keys(self::MAP), array_values(self::MAP), $s);
    }
}
