<?php
return [
    'stripe' => [
        'model' => App\Models\User::class,
~>        'secret' => '@@sample:[A-Za-z0-9]{32}@@',
    ],
];
