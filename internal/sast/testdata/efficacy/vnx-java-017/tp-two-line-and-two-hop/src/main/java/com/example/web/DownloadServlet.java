package com.example.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String name = req.getParameter("name");
        String disposition = "attachment; filename=" + name;
~>        res.setHeader("Content-Disposition", disposition);

        String back = req.getParameter("back");
        if (back != null) {
~>            res.sendRedirect(back);
        }
        String tracking = req.getHeader("X-Tracking-Id");
~>        res.addHeader("X-Tracking-Id", tracking);
    }
}
