package com.acme.web;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.*;

public class UploadServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        try {
            store(req);
            out.println("ok");
        } catch (Exception e) {
~>            e.printStackTrace(out);
        }
    }
}
