package com.acme.web;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
~>        File report = new File("/var/reports/" + request.getParameter("name"));
~>        try (FileInputStream in = new FileInputStream(req(request).getParameter("alt"))) {
            in.transferTo(response.getOutputStream());
        }
    }

    private HttpServletRequest req(HttpServletRequest r) {
        return r;
    }
}
