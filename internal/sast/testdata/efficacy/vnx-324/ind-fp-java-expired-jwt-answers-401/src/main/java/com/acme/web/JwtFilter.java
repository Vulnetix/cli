package com.acme.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);
    private final JwtParser parser;

    public JwtFilter(JwtParser parser) {
        this.parser = parser;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String token = req.getHeader("Authorization");
        try {
            Claims claims = parser.parseClaimsJws(token.substring(7)).getBody();
            req.setAttribute("user", claims.getSubject());
        } catch (ExpiredJwtException e) {
            log.info("expired token for subject {}", e.getClaims().getSubject());
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "token expired");
            return;
        }
        chain.doFilter(req, res);
    }
}
