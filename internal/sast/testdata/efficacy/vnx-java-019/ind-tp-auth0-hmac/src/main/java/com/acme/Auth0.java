package com.acme;
import com.auth0.jwt.algorithms.Algorithm;
public class Auth0 {
    Algorithm alg() {
~>        return Algorithm.HMAC256("hunter2-signing-secret-value");
    }
}
