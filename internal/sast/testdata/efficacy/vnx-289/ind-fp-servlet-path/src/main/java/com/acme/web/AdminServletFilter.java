package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.*;

public class AdminServletFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        if (request.getServletPath().startsWith("/admin") && !request.isUserInRole("ADMIN")) {
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        chain.doFilter(req, res);
    }
}
