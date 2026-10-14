<?php
~>mb_regex_set_options('pze');
function expand($s)
{
~>    return mb_ereg_replace(
        '\[(\d+)\]',
        'str_repeat("*", \\1)',
        $s,
        'ex'
    );
}
