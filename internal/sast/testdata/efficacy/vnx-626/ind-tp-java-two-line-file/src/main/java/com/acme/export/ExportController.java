package com.acme.export;

import java.io.File;
import java.nio.file.Files;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExportController {
    private final File exportDir = new File("/data/exports");

    public void download(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
~>        File f = new File(exportDir, name + ".csv");
        Files.copy(f.toPath(), resp.getOutputStream());
    }
}
