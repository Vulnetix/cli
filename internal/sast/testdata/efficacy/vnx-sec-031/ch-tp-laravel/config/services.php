<?php

return [
    'mailgun' => [
        'domain' => 'mg.acme.example',
~>        'secret' => '@@sample:[a-f0-9]{32}@@-@@sample:[a-f0-9]{8}@@-@@sample:[a-f0-9]{8}@@',
        'endpoint' => 'api.eu.mailgun.net',
    ],
];
