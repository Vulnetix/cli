package com.acme.web;

import javax.servlet.FilterChain;

public class AuthFilter extends OncePerRequestFilter {
    @Override
    @SuppressWarnings("unchecked")
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain)
            throws Exception {
        chain.doFilter(req, res);
    }

    @Override
    public void destroy() throws Exception { }
}
