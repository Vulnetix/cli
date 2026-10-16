package com.acme.api;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(urlPatterns = "/tenant/*")
public class TenantServlet extends HttpServlet {
    private String tenant;
    private Object principal;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String t = request.getHeader("X-Tenant-Id");
        if (t == null) {
            response.sendError(400);
            return;
        }
~>        tenant = t;
~>        principal = request.getUserPrincipal();
        response.getWriter().println(lookup(tenant, principal));
    }
}
