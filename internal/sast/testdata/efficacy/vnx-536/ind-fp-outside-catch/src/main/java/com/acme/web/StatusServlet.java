package com.acme.web;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class StatusServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        ValidationResult result = Validator.check(request.getParameter("sku"));
        if (!result.ok()) {
            response.setStatus(400);
            out.println("Invalid SKU: " + result.getMessage());
            return;
        }
        // On failure we used to do e.printStackTrace(response.getWriter()); no longer.
        out.println("{\"status\": \"ok\"}");
    }
}
