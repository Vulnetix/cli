<?php
$warning = 'Never call extract($_POST) or parse_str($qs) without a result array';
echo "Avoid foreach (\$_GET as \$k => \$v) { \$\$k = \$v; }";
parse_str(
    $query,
    $params
);
mb_parse_str($query, $out);
$zip->extractTo('/tmp/out');
