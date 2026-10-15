package io.acme;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;

public class SignedTokens {
    private final SecretKey key;
    SignedTokens(SecretKey key) { this.key = key; }

    public Jwt<?, ?> read(String token) {
        return Jwts.parser().verifyWith(key).build().parse(token);
    }

    public Object payload(String token) {
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parse(token)
            .getPayload();
    }
}
