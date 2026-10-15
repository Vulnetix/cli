package com.acme.web;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.*;
import javax.servlet.http.*;

public class AdminFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        String uri = request.getRequestURI();
~>        if (uri.startsWith("/admin") && !isAdmin(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        String resource = URLDecoder.decode(uri, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        request.setAttribute("resource", resource);
        chain.doFilter(req, res);
    }

    private boolean isAdmin(HttpServletRequest request) {
        return request.isUserInRole("ADMIN");
    }
}
