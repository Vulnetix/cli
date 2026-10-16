<?php
$s = mb_ereg_replace('[^\w\s-]', '', $s, 'msr');
$t = mb_ereg_replace('\s+', ' ', $t);
$u = mb_eregi_replace('colour', 'color', $u, 'i');
mb_regex_set_options('pr');
