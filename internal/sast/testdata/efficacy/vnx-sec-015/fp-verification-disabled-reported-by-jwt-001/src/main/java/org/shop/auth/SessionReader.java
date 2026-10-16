package org.shop.auth;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

// jjwt parse() after setSigningKey accepts an unsigned token; VNX-JWT-001
// reports it as signature verification skipped.
public class SessionReader {
    private static final byte[] KEY = Keys.load();

    public Object inline(String bearer) {
        Jwt<?, ?> jwt = Jwts.parser().setSigningKey(KEY).parse(bearer);
        return jwt.getBody();
    }

    public Object chained(String bearer) {
        return Jwts.parser()
            .setSigningKey(KEY)
            .parse(bearer)
            .getBody();
    }
}
