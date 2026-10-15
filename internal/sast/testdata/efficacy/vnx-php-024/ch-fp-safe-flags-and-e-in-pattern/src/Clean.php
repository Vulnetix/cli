<?php
function clean_text(string $s): string
{
    $s = mb_ereg_replace('e', 'E', $s);
    $s = mb_ereg_replace('\s+', ' ', $s, 'msr');
    $s = mb_eregi_replace('hello', 'bye', $s, 'i');
    $s = mb_ereg_replace('[ée]', 'e', $s, 'x');
    return mb_ereg_replace(trim_pattern('ee'), replacement('e'), $s, 'p');
}
