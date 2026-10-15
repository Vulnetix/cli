<?php
use Aws\S3\S3Client;

$client = new S3Client([
    'region' => 'us-east-1',
    'version' => 'latest',
    'credentials' => [
        'key' => getenv('AWS_ACCESS_KEY_ID'),
~>        'secret' => '@@sample:[A-Za-z0-9/+]{40}@@',
    ],
]);
