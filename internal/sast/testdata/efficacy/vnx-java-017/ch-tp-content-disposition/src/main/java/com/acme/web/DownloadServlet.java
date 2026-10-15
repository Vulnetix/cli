package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("application/octet-stream");
~>        response.setHeader("Content-Disposition", "attachment; filename=\"" + request.getParameter("name") + "\"");
        response.getOutputStream().write(new byte[0]);
    }
}
