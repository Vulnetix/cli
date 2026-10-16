package com.acme.web;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;

public class CspFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) res;
~>        response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd' 'strict-dynamic'");
        chain.doFilter(req, res);
    }
}
