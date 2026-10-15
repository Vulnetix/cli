package com.example.upload;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {

    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
        String name = file.getOriginalFilename();
~>        if (name.endsWith(".jsp") || name.endsWith(".jspx")) {
            throw new IllegalArgumentException("not allowed");
        }
        String ext = name.substring(name.lastIndexOf('.') + 1);
~>        if ("exe".equals(ext)) {
            throw new IllegalArgumentException("not allowed");
        }
        return store(file, name);
    }
}
