<?php
function upper_words(string $s): string
{
    $current = mb_regex_set_options();
    mb_regex_set_options('pr');
    $out = mb_ereg_replace_callback('\w+', function ($m) {
        return mb_strtoupper($m[0]);
    }, $s, 'msr');
    mb_regex_set_options($current);
    return $out;
}
