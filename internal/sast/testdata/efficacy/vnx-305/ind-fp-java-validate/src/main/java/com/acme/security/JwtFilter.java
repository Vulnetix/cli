package com.acme.security;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtFilter implements Filter {
    private final JwtValidator validator;

    public JwtFilter(JwtValidator validator) {
        this.validator = validator;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        String header = ((HttpServletRequest) req).getHeader("Authorization");
        if (header != null && validator.validateToken(header.substring(7))) {
            chain.doFilter(req, res);
            return;
        }
        ((HttpServletResponse) res).sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
