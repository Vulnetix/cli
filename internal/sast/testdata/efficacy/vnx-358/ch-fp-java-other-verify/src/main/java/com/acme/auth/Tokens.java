package com.acme.auth;

import javax.net.ssl.SSLSession;

public class Tokens {
    // SSLSession is logged below; this verifier checks API tokens, not hosts
    public boolean verify(String token, String issuer) {
        return token.startsWith("tok_") && issuer.endsWith(".acme.com");
    }

    public void log(SSLSession session) {
        System.out.println(session.getPeerHost());
    }
}
