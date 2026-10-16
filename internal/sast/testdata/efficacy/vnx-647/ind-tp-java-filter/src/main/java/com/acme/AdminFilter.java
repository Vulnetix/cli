package com.acme;

import javax.servlet.http.*;

public class AdminFilter {
    void check(HttpServletRequest request, HttpServletResponse response) throws Exception {
~>        if (request.getRequestURI().startsWith("/admin") && !isAdmin(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
    }
}
