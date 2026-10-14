package com.acme.files;

import java.io.File;
import java.nio.file.Files;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AttachmentServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String name = req.getParameter("file");
        File f = new File("/data/attachments", name);
~>        Files.copy(f.toPath(), resp.getOutputStream());
    }
}
