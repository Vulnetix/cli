package com.acme;

import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;

public class Config extends HttpServlet {
    private static final String CFG = "/etc/acme/app.properties";

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        File f = new File(CFG);
        try (FileInputStream in = new FileInputStream(f)) {
            in.read();
        }
        String body = request.getParameter("note");
        Files.writeString(Paths.get("/var/log/acme/notes.log"), body);
    }
}
