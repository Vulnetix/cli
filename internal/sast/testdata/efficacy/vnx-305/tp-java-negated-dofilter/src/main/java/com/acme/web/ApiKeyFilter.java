package com.acme.web;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

public class ApiKeyFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
        String apiKey = ((HttpServletRequest) req).getHeader("X-Api-Key");
        if (apiKey == null) {
            ((HttpServletResponse) res).sendError(401);
            return;
        }
~>        filterChain.doFilter(req, res);
    }
}
