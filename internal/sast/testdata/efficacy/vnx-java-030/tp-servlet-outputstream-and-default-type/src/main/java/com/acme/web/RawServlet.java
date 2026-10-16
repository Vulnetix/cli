package com.acme.web;

import java.io.IOException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RawServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        String msg = request.getParameter("msg");
~>        response.getOutputStream().write(("<p>" + msg + "</p>").getBytes());
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String uri = request.getRequestURI();
        ServletOutputStream os = response.getOutputStream();
~>        os.write(uri.getBytes("UTF-8"));
    }

    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // no setContentType: the container default for a writer is text/html
~>        response.getWriter().print("Not found: " + request.getRequestURL());
    }
}
