<?php
function looks_like_email($s)
{
    return preg_match('/^[^@]+@[^@]+$/', $s) === 1;
}

function slugify($s)
{
    $s = preg_replace('/[^a-z0-9]+/i', '-', $s);
    return preg_replace('#-+#u', '-', trim($s, '-'));
}
