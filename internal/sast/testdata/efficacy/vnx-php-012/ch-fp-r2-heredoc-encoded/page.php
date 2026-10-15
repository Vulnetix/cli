<?php
$name = htmlspecialchars($_GET['name'], ENT_QUOTES);
echo <<<HTML
<h1>Hello $name</h1>
HTML;
$raw = $_GET['raw'];
echo <<<'TXT'
<p>$raw is shown literally</p>
TXT;
$q = $_GET['q'];
$sql = <<<SQL
SELECT 1
SQL;
