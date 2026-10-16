package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String region =
                request.getParameter("region");
~>        response.getWriter()
                .println(
                        "Report for: "
                                + region
                                + " generated.");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String label = request.getParameter("label");
        Object[] extra = {"a", "b"};
~>        response.getWriter().printf("<li>" + label + "</li>%s %s", extra);
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String label = request.getParameter("label");
~>        response.getWriter().format(java.util.Locale.US, "<li>%s</li>", label);
    }
}
