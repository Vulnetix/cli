package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;

public class CspFilter implements Filter {
    private static final String CSP =
~>        "script-src 'self' 'nonce-r4nd0mStatic'; object-src 'none'";

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        ((HttpServletResponse) res).setHeader("Content-Security-Policy", CSP);
        chain.doFilter(req, res);
    }
}
