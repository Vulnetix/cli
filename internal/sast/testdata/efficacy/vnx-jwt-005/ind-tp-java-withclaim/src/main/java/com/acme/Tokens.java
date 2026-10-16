package com.acme;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class Tokens {
    public String make(User u, Algorithm alg) {
        return JWT.create()
                .withSubject(u.getId())
~>                .withClaim("password", u.getPassword())
                .sign(alg);
    }
}
