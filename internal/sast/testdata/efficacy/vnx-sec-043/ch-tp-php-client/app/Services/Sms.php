<?php
use Twilio\Rest\Client;

~>$twilio = new Client('@@sample:SK[0-9a-f]{32}@@', $apiSecret, $accountSid);
