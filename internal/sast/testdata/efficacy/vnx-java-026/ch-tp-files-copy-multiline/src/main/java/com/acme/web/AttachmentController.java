package com.acme.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AttachmentController {
    private static final String UPLOAD_DIR = "/data/attachments/";

    @GetMapping("/attachments")
    public void attachment(
            @RequestParam("path") String path,
            HttpServletResponse response) throws IOException {
        response.setHeader("Content-Disposition", "attachment");
~>        Files.copy(Paths.get(UPLOAD_DIR + path), response.getOutputStream());
    }
}
