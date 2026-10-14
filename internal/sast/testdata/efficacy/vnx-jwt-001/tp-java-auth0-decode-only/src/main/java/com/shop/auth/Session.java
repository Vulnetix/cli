package com.shop.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import javax.servlet.http.HttpServletRequest;

public class Session {
  public String user(HttpServletRequest request) {
    String token = request.getHeader("Authorization").substring(7);
~>    DecodedJWT jwt = JWT.decode(token);
    return jwt.getSubject();
  }
}
