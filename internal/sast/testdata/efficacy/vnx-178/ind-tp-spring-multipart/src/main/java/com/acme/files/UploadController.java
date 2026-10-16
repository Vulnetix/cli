package com.acme.files;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UploadController {

    private final Path root = Paths.get("webapps/ROOT/uploads");

    @PostMapping("/upload")
    public ResponseEntity<String> upload(@RequestParam("file") MultipartFile file) throws IOException {
        String filename = file.getOriginalFilename();
~>        if (filename.endsWith(".jsp") || filename.endsWith(".jspx")) {
            return ResponseEntity.badRequest().body("JSP uploads are not allowed");
        }
        file.transferTo(root.resolve(filename));
        return ResponseEntity.ok("stored");
    }
}
