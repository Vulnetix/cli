package com.acme.files;

import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DownloadController {
    private final String uploadDir = "/srv/uploads/";
    private final Path root = Paths.get("/srv/uploads");

    @GetMapping("/download/{filename}")
    public ResponseEntity<Resource> download(@PathVariable String filename) {
~>        Resource resource = new FileSystemResource(uploadDir + filename);
        return ResponseEntity.ok().body(resource);
    }

    @GetMapping("/files/{name:.+}")
    public ResponseEntity<Resource> serve(@PathVariable("name") final String name) throws Exception {
        Path file = root.resolve(name);
~>        Resource resource = new UrlResource(file.toUri());
        return ResponseEntity.ok(resource);
    }
}
