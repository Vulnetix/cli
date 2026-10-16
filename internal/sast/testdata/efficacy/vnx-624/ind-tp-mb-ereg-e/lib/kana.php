<?php
mb_regex_encoding('UTF-8');

function upper_words($s)
{
~>    return mb_ereg_replace('(\w+)', "mb_strtoupper('\\1')", $s, 'e');
}
