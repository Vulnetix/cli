package com.acme;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.*;

public class InternalFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest http = (HttpServletRequest) req;
        String target = http.getRequestURI();
~>        if (target.startsWith("/internal/") && !"10.0.0.5".equals(http.getRemoteAddr())) {
            ((HttpServletResponse) res).sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(req, res);
    }
}
