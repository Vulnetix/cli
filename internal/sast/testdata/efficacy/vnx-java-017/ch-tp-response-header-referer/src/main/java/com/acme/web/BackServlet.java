package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BackServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse httpServletResponse) throws IOException {
        String back = req.getHeader("Referer");
~>        httpServletResponse.setHeader("Refresh", "0; url=" + back);
    }
}
