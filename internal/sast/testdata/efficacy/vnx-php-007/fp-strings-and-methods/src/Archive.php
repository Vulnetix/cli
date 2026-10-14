<?php
// extract($_POST) would let a client overwrite $is_admin
class Archive
{
    public function extract($to)
    {
        return $this->zip->extractTo($to);
    }
}
$zip->extract($_GET["dir"]);
echo "never call extract(\$_GET)";
$doc = 'parse_str($_SERVER["QUERY_STRING"]);';
