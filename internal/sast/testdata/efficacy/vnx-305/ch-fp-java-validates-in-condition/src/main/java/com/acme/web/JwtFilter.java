package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtFilter implements Filter {
    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService) { this.jwtService = jwtService; }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        String header = ((HttpServletRequest) req).getHeader("Authorization");
        if (header != null && jwtService.isTokenValid(header.substring(7))) {
            chain.doFilter(req, res);
            return;
        }
        ((HttpServletResponse) res).sendError(401);
    }
}
