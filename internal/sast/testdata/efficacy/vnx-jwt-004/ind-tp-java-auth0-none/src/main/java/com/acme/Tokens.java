package com.acme;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class Tokens {
    public String make(String sub) {
~>        Algorithm alg = Algorithm.none();
        return JWT.create().withSubject(sub).sign(alg);
    }
}
