package com.acme.web;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

public class TokenFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        String authToken = request.getHeader("Authorization");
~>        if (authToken != null && authToken.startsWith("Bearer ")) {
            chain.doFilter(req, res);
            return;
        }
        ((HttpServletResponse) res).sendError(401);
    }
}
