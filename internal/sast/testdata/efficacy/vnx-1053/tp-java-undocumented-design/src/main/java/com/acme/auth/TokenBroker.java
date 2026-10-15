package com.acme.auth;

/**
~> * Undocumented design: tokens are minted here and also in the gateway.
 */
public final class TokenBroker {
~>    // design docs are missing for the refresh flow
    public String mint(String subject) {
        return subject;
    }
}
