<?php
function slug($s)
{
    $s = mb_ereg_replace('[^\w\s-]', '', $s, 'msr');
    $s = mb_eregi_replace('\s+', '-', $s, "i");
    $opts = 'x';
    $s = mb_ereg_replace('a  b', 'ab', $s, $opts);
    mb_regex_set_options('msr');
    return mb_ereg_replace('-+', '-', $s, $this->options);
}
