package com.acme.web;

import javax.servlet.*;
import javax.servlet.http.*;

public class AdminFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws java.io.IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
~>        if (request.getRequestURI().startsWith("/admin") && request.getSession().getAttribute("admin") == null) {
            response.sendError(403);
            return;
        }
        String uri = request.getRequestURI();
~>        if (uri.equals("/internal/metrics")) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(req, res);
    }
}
