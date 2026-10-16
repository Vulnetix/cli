package com.acme.files;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/attachments")
public class AttachmentController {
    private final Path root = Paths.get("/srv/attachments");

    @GetMapping
    public ResponseEntity<byte[]> get(@RequestParam String file) throws IOException {
        Path p = root.resolve(file);
~>        return ResponseEntity.ok(Files.readAllBytes(p));
    }
}
