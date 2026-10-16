package com.acme;

import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class SafeUpload {
    @PostMapping("/upload")
    public String upload(@RequestParam("f") MultipartFile file) throws IOException {
        String clean = FilenameUtils.getName(file.getOriginalFilename());
        File dest = new File("/uploads", clean);
        file.transferTo(dest);
        return "ok";
    }
}
