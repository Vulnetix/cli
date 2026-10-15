<?php
~>$ch = curl_init('http://crm.partner-corp.net/api/contacts');
~>$body = file_get_contents("http://feeds.partner-corp.net/prices.json");
~>$config = ['api_base' => 'http://crm.partner-corp.net'];
