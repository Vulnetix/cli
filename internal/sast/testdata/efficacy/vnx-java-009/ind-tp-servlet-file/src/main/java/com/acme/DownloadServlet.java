package com.acme;

import java.io.*;
import javax.servlet.http.*;

public class DownloadServlet extends HttpServlet {
    private static final String BASE = "/var/data/reports";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("file");
        response.setContentType("application/octet-stream");
~>        File target = new File(BASE, name);
        try (InputStream in = new FileInputStream(target);
             OutputStream out = response.getOutputStream()) {
            in.transferTo(out);
        }
    }
}
