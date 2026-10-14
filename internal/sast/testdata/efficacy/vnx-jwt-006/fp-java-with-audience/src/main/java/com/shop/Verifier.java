package com.shop;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class Verifier {
  public Object verify(String token, Algorithm algorithm, JwkProvider provider) {
    return JWT.require(algorithm).withAudience("orders-api").withIssuer("https://tenant.example.com/").build().verify(token);
  }
}
