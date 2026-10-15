package com.shop.web;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.*;
import javax.servlet.http.*;

public class LoginFilter implements Filter {
    public void doFilter(ServletRequest r, ServletResponse s, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) r;
        String uri = request.getRequestURI();
~>        if (!"/login".equals(uri) && request.getSession(false) == null) {
            ((HttpServletResponse) s).sendRedirect("/login");
            return;
        }
        Path resolved = Paths.get(uri).normalize();
        request.setAttribute("resolved", resolved.toString());
        chain.doFilter(r, s);
    }
}
