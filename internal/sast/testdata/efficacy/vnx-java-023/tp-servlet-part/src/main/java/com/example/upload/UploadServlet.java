package com.example.upload;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

@MultipartConfig
public class UploadServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        String uploadPath = getServletContext().getRealPath("") + File.separator + "uploads";
~>        filePart.write(uploadPath + File.separator + fileName);

        Part second = request.getPart("attachment");
        String n2 = second.getSubmittedFileName();
        File dest = new File(uploadPath, n2);
~>        try (FileOutputStream out = new FileOutputStream(dest)) {
            second.getInputStream().transferTo(out);
        }
    }
}
