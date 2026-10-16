package com.acme.jobs;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CleanupServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String text = label(request.getParameter("who"));
        Runtime.getRuntime().exec("echo " + text);
        String kept = keep(request, "fixed");
        Runtime.getRuntime().exec("echo " + kept);
    }

    private String label(String raw) {
        return "job";
    }

    private static String keep(HttpServletRequest request, String value) {
        String copy = value;
        return copy;
    }
}
