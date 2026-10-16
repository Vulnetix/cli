package com.acme.upload;

import java.io.File;
import java.io.IOException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UploadController {

    private final File dir = new File("/srv/uploads");

    @PostMapping("/upload")
    public ResponseEntity<String> upload(@RequestParam("file") MultipartFile file) throws IOException {
~>        file.transferTo(new File(dir, file.getOriginalFilename()));
        return ResponseEntity.ok("stored");
    }
}
