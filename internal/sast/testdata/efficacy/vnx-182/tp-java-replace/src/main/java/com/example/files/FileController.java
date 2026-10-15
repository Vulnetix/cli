package com.example.files;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class FileController {
    private static final Path ROOT = Paths.get("/var/app/uploads");

    public byte[] read(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
~>        name = name.replace("../", "");
        return Files.readAllBytes(ROOT.resolve(name));
    }

    public byte[] readLegacy(HttpServletRequest request) throws Exception {
~>        String name = request.getParameter("file").replaceAll("\\.\\./", "");
        return Files.readAllBytes(ROOT.resolve(name));
    }

    public String title(HttpServletRequest request) {
~>        return request.getParameter("title").replaceAll("(?i)<script>", "");
    }
}
