package com.acme.web;

import java.io.IOException;
import javax.servlet.http.*;

public class Hdr {
    void bounce(HttpServletRequest req, HttpServletResponse resp) {
        String dest = req.getParameter("dest");
        resp.setStatus(302);
~>        resp.setHeader("Location", dest);
    }
}
