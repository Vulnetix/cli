<?php
$menu[] = ["id" => "phpinfo", "name" => "PHP Info", "url" => "phpinfo.php"];
$rule = new RequiredIf("phpinfo");
echo "Run phpinfo() to see your configuration";
$diag->phpinfo();
Diagnostics::phpinfo();
function phpinfo_section($name) { return $name; }
