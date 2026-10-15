package com.acme.files;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {
    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) {
        String fileName = file.getOriginalFilename();
~>        if (fileName.endsWith(".jsp") ||
~>                fileName.endsWith(".jspx")) {
            return "rejected";
        }
        store(file);
        return "ok";
    }
}
