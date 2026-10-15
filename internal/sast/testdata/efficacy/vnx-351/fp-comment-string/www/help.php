<?php
// in_array($_GET['role'], $allowed) is loose; pass true as the third argument.
$help = "Never call in_array($_GET[x], $list) without strict mode";
