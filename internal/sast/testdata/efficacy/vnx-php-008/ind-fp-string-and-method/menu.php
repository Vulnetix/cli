<?php
$menu = ["phpinfo" => "PHP Info", "logs" => "Logs"];
$tool->phpinfo();
// phpinfo();
$help = <<<TXT
Run phpinfo() to see settings
TXT;
echo $help;
