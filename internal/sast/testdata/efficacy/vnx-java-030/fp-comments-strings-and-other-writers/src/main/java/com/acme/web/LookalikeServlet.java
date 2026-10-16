package com.acme.web;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LookalikeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        String name = request.getParameter("name");
        // response.getWriter().println("<p>" + name + "</p>");
        /* response.getWriter().write(name); */
        String doc = "response.getWriter().println(name)";
        response.getWriter().println(doc);
        response.getWriter().println("request.getParameter(\"name\")");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        PrintWriter audit = new PrintWriter(new FileWriter(new File("/var/log/app/audit.log"), true));
        audit.println("note: " + note);
        audit.close();
        FileWriter log = new FileWriter("/var/log/app/notes.log");
        log.write(note);
        log.close();
        StringBuilder sb = new StringBuilder();
        sb.append(note);
        response.setStatus(204);
    }
}
