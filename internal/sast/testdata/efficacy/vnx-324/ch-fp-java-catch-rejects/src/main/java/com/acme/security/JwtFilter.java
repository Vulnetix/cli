package com.acme.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtFilter {
    private final byte[] key;

    public JwtFilter(byte[] key) {
        this.key = key;
    }

    public boolean authenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getHeader("Authorization");
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            request.setAttribute("subject", claims.getSubject());
            return true;
        } catch (ExpiredJwtException e) {
            log("expired token for " + e.getClaims().getSubject());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "token expired");
            return false;
        }
    }

    private void log(String msg) {
        System.err.println(msg);
    }
}
