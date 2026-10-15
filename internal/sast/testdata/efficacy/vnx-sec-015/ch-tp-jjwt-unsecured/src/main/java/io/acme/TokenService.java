package io.acme;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class TokenService {
    public Claims claims(String token) {
        return Jwts.parser()
~>            .unsecured()
            .build()
~>            .parseUnsecuredClaims(token)
            .getPayload();
    }
}
