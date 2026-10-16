package com.acme;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class Tokens {
    public String make(String sub, byte[] key) {
        return JWT.create().withSubject(sub).sign(Algorithm.HMAC256(key));
    }
}
