package com.acme.auth;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenFilter {
    private static final Logger log = LoggerFactory.getLogger(TokenFilter.class);
    private final JWTVerifier verifier;

    public TokenFilter(JWTVerifier verifier) {
        this.verifier = verifier;
    }

    public String subject(String token) {
        try {
            verifier.verify(token);
~>        } catch (JWTVerificationException e) {
            log.warn("token verification failed: {}", e.getMessage());
        }
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getSubject();
    }
}
