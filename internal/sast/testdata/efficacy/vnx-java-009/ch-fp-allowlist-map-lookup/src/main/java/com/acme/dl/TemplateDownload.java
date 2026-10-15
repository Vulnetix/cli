package com.acme.dl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TemplateDownload extends HttpServlet {
    private static final Map<String, String> TEMPLATES = Map.of(
        "invoice", "invoice-v3.docx",
        "letter", "letter.docx");
    private static final File DIR = new File("/srv/templates");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String kind = request.getParameter("kind");
        String fileName = TEMPLATES.get(kind);
        if (fileName == null) {
            response.sendError(404);
            return;
        }
        response.getOutputStream().write(Files.readAllBytes(new File(DIR, fileName).toPath()));
    }
}
