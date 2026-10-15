package com.acme.upload;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import org.springframework.web.multipart.MultipartFile;

@MultipartConfig
public class UploadServlet extends HttpServlet {
    private static final String UPLOAD_DIR = "D:\\uploads";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        Part part = request.getPart("file");
        String name = part.getSubmittedFileName();
~>        part.write(UPLOAD_DIR + File.separator + name);
    }

    public void store(MultipartFile file) throws IOException {
        Path dir = Paths.get(UPLOAD_DIR);
~>        Files.copy(file.getInputStream(), dir.resolve(file.getOriginalFilename()));
    }
}
