<?php
$pattern = $_GET['q'] ?? '';
~>$handle = popen(
    'grep -rn ' . $pattern . ' /var/www/docs',
    'r'
);
~>system("tar czf /tmp/export.tgz " . $_POST["dir"]);
~>$ok = proc_open(
    "ffmpeg -i " . $_FILES['clip']['name'] . " out.mp4",
    [1 => ['pipe', 'w']],
    $pipes
);
~>$result = eval("return " . $_GET['formula'] . ";");
