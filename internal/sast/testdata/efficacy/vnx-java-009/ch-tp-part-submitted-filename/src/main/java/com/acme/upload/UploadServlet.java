package com.acme.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

public class UploadServlet extends HttpServlet {
    private final String uploadDir = "/var/app/uploads";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            Part part = request.getPart("document");
            String fn = part.getSubmittedFileName();
~>            Files.copy(part.getInputStream(), Paths.get(uploadDir, fn));
            response.setStatus(201);
        } catch (javax.servlet.ServletException e) {
            response.sendError(400);
        }
    }
}
