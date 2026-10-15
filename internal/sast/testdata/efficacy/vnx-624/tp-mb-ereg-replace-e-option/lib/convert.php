<?php
~>$s = mb_ereg_replace('([a-z]+)', 'strtoupper("\\1")', $s, 'e');
~>$t = mb_eregi_replace($pattern, $replacement, $t, "msre");
