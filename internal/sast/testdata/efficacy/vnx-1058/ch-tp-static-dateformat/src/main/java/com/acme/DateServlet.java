package com.acme;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DateServlet extends HttpServlet {
~>    private static SimpleDateFormat stamp = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Date when = stamp.parse(req.getParameter("at"), new java.text.ParsePosition(0));
        resp.getWriter().write(stamp.format(when));
    }
}
