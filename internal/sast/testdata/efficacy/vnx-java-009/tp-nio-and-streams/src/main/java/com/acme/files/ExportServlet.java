package com.acme.files;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class ExportServlet {
    void handle(HttpServletRequest request) throws Exception {
        Map<String, String[]> params = request.getParameterMap();
        String out = params.get("out")[0];
~>        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(1);
        }
        String log = request.getPathInfo();
~>        FileWriter w = new FileWriter("/var/log/app" + log, true);
        String idx = request.getQueryString();
~>        RandomAccessFile raf = new RandomAccessFile(idx, "r");
~>        byte[] data = Files.readAllBytes(Paths.get(request.getParameter("f")));
    }
}
