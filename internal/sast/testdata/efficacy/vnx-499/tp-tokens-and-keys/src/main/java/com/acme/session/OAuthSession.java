package com.acme.session;

import java.io.Serializable;
import java.security.PrivateKey;

public class OAuthSession extends BaseSession implements Comparable<OAuthSession>, Serializable {
~>    private String accessToken;
~>    protected String refreshToken;
~>    private PrivateKey signingKey;
~>    String clientSecret = "";
~>    public byte[] apiKey;
    private long expiresAt;

    public int compareTo(OAuthSession o) {
        return Long.compare(expiresAt, o.expiresAt);
    }
}
