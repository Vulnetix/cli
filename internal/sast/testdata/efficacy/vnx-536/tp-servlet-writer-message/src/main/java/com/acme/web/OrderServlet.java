package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OrderServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            process(request);
        } catch (Exception e) {
~>            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            save(req);
        } catch (IllegalStateException | IOException ex) {
~>            ex.printStackTrace(resp.getWriter());
        } catch (RuntimeException err) {
~>            resp.getWriter().write(err.toString());
        }
    }
}
