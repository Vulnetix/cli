<?php

namespace App\Lib;

final class Filter
{
    public static function strip(string $input): string
    {
        $out = str_ireplace(['<script>', '</script>'], '', $input);
        $out = preg_replace('/<iframe\b[^>]*>.*?<\/iframe>/is', '', $out);
        return htmlspecialchars($out, ENT_QUOTES, 'UTF-8');
    }

    public static function hasScript(string $input): bool
    {
        return stripos($input, '<script') !== false;
    }
}
