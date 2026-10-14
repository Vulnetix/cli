<?php
$clean = mb_ereg_replace('\s+', ' ', 'the quick brown fence');
$name = mb_ereg_replace('e', 'E', $name);
$upper = mb_ereg_replace_callback('\b(\w)', fn($m) => mb_strtoupper($m[1]), $title, 'msr');
$x = mb_ereg_replace($pattern, $replacement, $subject);
