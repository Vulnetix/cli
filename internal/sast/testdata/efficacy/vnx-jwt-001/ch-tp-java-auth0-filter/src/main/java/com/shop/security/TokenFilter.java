package com.shop.security;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]in[t]er[f]ac[e]s[.][D]ec[o]de[d]JW[T]@@;
import jakarta.servlet.http.HttpServletRequest;

public class TokenFilter {
    public String userFrom(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
~>        DecodedJWT decoded = JWT.decode(header.substring(7));
        return decoded.getSubject();
    }
}
