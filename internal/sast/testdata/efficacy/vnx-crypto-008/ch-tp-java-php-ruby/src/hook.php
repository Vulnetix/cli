<?php
~>if ($signature == hash_hmac('sha256', $payload, $secret)) {
    accept();
}
