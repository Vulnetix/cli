package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ThumbnailServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int quality = Integer.parseInt(req.getParameter("q"));
~>        byte qByte = (byte) quality;
~>        short width = (short) Integer.parseInt(req.getParameter("w"));
~>        int maxBytes = (int) Long.parseLong(req.getParameter("max"));
        byte[] img = ThumbnailService.render(qByte, width, maxBytes);
        resp.setContentType("image/jpeg");
        resp.getOutputStream().write(img);
    }
}
