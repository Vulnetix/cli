package com.acme.security;

import javax.servlet.*;
import javax.servlet.http.*;

public class AdminFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws java.io.IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
~>        if (request.getRequestURI().startsWith("/admin") && !isAdmin(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        String uri = request.getRequestURI();
~>        if (uri.equals("/api/internal/metrics") && request.getUserPrincipal() == null) {
            response.sendError(401);
            return;
        }
        chain.doFilter(req, res);
    }
}
