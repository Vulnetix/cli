package com.acme.upload;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UploadController {
    @PostMapping("/documents")
    public ResponseEntity<String> upload(@RequestParam("file") MultipartFile file) {
        String fileName = file.getOriginalFilename();
~>        if (!fileName.contains(".pdf")) {
            return ResponseEntity.badRequest().body("PDF only");
        }
~>        String ext = fileName.split("\\.")[1];
        storage.save(file, ext);
        return ResponseEntity.ok("stored");
    }
}
