<?php

namespace App\Http\Controllers;

use League\OAuth2\Client\Provider\GenericProvider;

class OAuthController
{
    public function redirect(GenericProvider $provider)
    {
        $authUrl = $provider->getAuthorizationUrl([
            'scope' => ['openid', 'profile'],
        ]);
~>        $url = $provider->getAuthorizationUrl(['state' => 'b4c0n']);
        header('Location: ' . $url);
        exit;
    }
}
