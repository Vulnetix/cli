package com.acme.files;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class FileServlet {
    private static final String BASE_DIR = "/srv/files";

    void doGet(HttpServletRequest request) throws Exception {
        FileInputStream in = new FileInputStream(request.getParameter("file"));
        String name = request.getParameter("name");
        File f = new File(BASE_DIR, name);
        in.close();
    }

    @GetMapping("/report")
    public byte[] report(@RequestParam("name") String filename) throws Exception {
        return Files.readAllBytes(Paths.get(BASE_DIR, filename));
    }
}
