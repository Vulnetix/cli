package com.acme.io;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class ReportWriter {
    public void write(byte[] data) throws IOException {
~>        Files.write(Paths.get("/tmp/acme-report.txt"), data);
    }

    public void upload(HttpServletRequest request, byte[] data) throws IOException {
~>        try (FileOutputStream out = new FileOutputStream(new File("/var/tmp/" + request.getParameter("name")))) {
            out.write(data);
        }
    }
}
