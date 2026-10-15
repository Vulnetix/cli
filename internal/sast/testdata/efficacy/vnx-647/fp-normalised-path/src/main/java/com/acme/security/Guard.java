package com.acme.security;

import java.net.URI;

public class Guard implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        HttpServletRequest request = (HttpServletRequest) req;
        String path = URI.create(request.getRequestURI()).normalize().getPath();
        if (path.startsWith("/admin") && !isAdmin(request)) {
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        if (request.getServletPath().startsWith("/admin") && !isAdmin(request)) {
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        chain.doFilter(req, res);
    }
}
