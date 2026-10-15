package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.*;

public class LoginExemptFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        if (req.getRequestURI().equals("/admin/login")) {
            chain.doFilter(request, response);
            return;
        }
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("admin") == null) {
            ((HttpServletResponse) response).sendRedirect("/admin/login");
            return;
        }
        chain.doFilter(request, response);
    }
}
