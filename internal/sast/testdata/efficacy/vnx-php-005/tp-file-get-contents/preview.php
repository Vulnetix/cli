<?php
~>$html = file_get_contents($_GET["url"]);
$url = $_POST["feed"];
~>$xml = file_get_contents( $url );
echo htmlspecialchars($html . $xml);
