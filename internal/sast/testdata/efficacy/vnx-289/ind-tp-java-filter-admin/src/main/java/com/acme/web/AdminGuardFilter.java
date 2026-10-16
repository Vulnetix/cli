package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.*;

public class AdminGuardFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        HttpSession session = request.getSession(false);
~>        if (request.getRequestURI().startsWith("/admin") && (session == null || session.getAttribute("admin") == null)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(req, res);
    }
}
