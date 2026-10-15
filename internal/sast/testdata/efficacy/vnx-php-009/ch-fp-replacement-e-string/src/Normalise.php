<?php
function normalise_path($p)
{
    $p = preg_replace('/\\\\/', '/', $p);
    $p = preg_replace('#/+#', '/', $p);
    $p = preg_replace('/\s+/', 'e', $p);
    return preg_replace('/^\.\/(.*)$/', '$1', $p);
}
