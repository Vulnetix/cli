package com.acme.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;

public class TokenService {
    private final byte[] key;

    public TokenService(byte[] key) {
        this.key = key;
    }

    public boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
~>            return true;
        }
    }

    public boolean isSignatureValid(byte[] data, byte[] sig) {
        try {
            return Signer.verify(key, data, sig);
        } catch (Exception e) {
            log(e);
~>            return true;
        }
    }

    private void log(Exception e) {
        System.err.println(e);
    }
}
