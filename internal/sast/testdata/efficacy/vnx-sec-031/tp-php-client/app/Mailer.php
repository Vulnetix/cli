<?php
use Mailgun\Mailgun;

~>$mg = Mailgun::create('key-@@sample:[0-9a-z]{32}@@');
$mg->messages()->send('mg.acme.example', ['to' => $to, 'subject' => 'Hi']);
