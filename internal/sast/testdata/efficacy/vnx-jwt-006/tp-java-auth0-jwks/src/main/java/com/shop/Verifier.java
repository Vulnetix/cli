package com.shop;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class Verifier {
  private final JwkProvider provider = new JwkProviderBuilder("https://tenant.example.com/").build();

  public DecodedJWT verify(String token, Algorithm algorithm) {
~>    return JWT.require(algorithm)
        .withIssuer("https://tenant.example.com/")
        .build()
        .verify(token);
  }
}
