<?php

$middleware->validateCsrfTokens(except: ['stripe/*', 'webhooks/github']);
$resolver->setDefaults(['csrf_protection' => true, 'csrf_field_name' => '_token']);
