<?php
function fetch_rates() {
~>    $json = file_get_contents("http://rates.acme-corp.org/latest.json");
    return json_decode($json, true);
}
