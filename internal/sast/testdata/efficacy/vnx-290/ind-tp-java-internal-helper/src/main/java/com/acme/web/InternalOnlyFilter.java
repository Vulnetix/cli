package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.*;

public class InternalOnlyFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest http = (HttpServletRequest) req;
~>        if (!NetworkPolicy.isInternal(http.getHeader("True-Client-IP"))) {
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        chain.doFilter(req, res);
    }
}
