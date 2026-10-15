package com.acme.sso;

class TokenCache {
~>    static volatile String accessToken;
~>    transient char[] credentials;
    private int size;
}
