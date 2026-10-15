package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UploadServlet {

    public void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
~>        if (req.getContentLength() > 5242880) {
~>            resp.sendError(413, "too large");
            return;
        }
        String name = req.getParameter("name");
~>        if (name == null || name.length() > 5242880) {
~>            resp.sendError(413);
            return;
        }
~>        if (req.getParts().size() * 1L > 5242880) {
~>            resp.setStatus(413);
        }
    }
}
