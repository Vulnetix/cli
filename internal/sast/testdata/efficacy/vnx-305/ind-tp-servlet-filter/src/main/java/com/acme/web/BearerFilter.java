package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BearerFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        String header = request.getHeader("Authorization");
~>        if (header != null && header.startsWith("Bearer ")) {
            chain.doFilter(req, res);
            return;
        }
        ((HttpServletResponse) res).sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
