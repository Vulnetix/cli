<?php
namespace App;

class LoginController
{
    public function redirect($provider)
    {
        $authUrl = $provider->getAuthorizationUrl([
            'scope' => ['openid', 'email'],
~>            'state' => 'loginstate2024',
        ]);
        header('Location: ' . $authUrl);
        exit;
    }
}
