package com.acme.upload;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.Part;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {
    private final String dir = "C:\\uploads";

    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
~>        file.transferTo(new File(dir, file.getOriginalFilename()));
        return "ok";
    }

    public void servletUpload(Part part) throws Exception {
        String name = FilenameUtils.getName(part.getSubmittedFileName());
        try (InputStream in = part.getInputStream()) {
~>            Files.copy(in, Paths.get(dir, name));
        }
    }
}
