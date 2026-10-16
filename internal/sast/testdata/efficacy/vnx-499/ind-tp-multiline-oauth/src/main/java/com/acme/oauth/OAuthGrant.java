package com.acme.oauth;

import java.io.Serializable;
import java.security.KeyPair;
import java.time.Instant;

public class OAuthGrant extends AbstractGrant
        implements Comparable<OAuthGrant>,
                   Serializable {
~>    private String refreshToken;
~>    protected String accessToken;
~>    private KeyPair keyPair;
    private Instant expiresAt;

    @Override
    public int compareTo(OAuthGrant other) {
        return expiresAt.compareTo(other.expiresAt);
    }
}
