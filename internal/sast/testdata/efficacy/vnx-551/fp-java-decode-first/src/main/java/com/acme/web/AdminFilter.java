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
        String uri = URLDecoder.decode(request.getRequestURI(), @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        String path = java.nio.file.Paths.get(uri).normalize().toString();
        if (path.startsWith("/admin") && !request.isUserInRole("ADMIN")) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(req, res);
    }

    public void check(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        String clean = new java.io.File("/srv", name).getCanonicalPath();
        if (!checkPermission(request.getRemoteUser(), clean)) {
            throw new SecurityException("denied");
        }
    }

    private boolean checkPermission(String u, String p) { return true; }
}
