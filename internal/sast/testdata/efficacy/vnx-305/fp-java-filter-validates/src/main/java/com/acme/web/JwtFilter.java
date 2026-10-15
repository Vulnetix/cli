package com.acme.web;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

public class JwtFilter implements Filter {
    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService) { this.jwtService = jwtService; }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        String token = ((HttpServletRequest) req).getHeader("Authorization");
        if (token != null) {
            jwtService.validateToken(token);
            chain.doFilter(req, res);
            return;
        }
        ((HttpServletResponse) res).sendError(401);
    }
}
