package com.acme;

import java.io.File;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UploadController {
    @PostMapping("/upload")
    public String upload(@RequestParam("f") MultipartFile file) throws IOException {
        String original = file.getOriginalFilename();
~>        File dest = new File("/uploads/" + original);
        file.transferTo(dest);
        return "ok";
    }
}
