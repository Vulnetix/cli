package com.acme.files;

import java.io.File;
import java.nio.file.Paths;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DownloadController {
    private static final String BASE = "/srv/files";

    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam("name") String fileName) {
        Resource r = new FileSystemResource(Paths.get(BASE, fileName));
        return ResponseEntity.ok(r);
    }

    @GetMapping("/raw")
    public ResponseEntity<Resource> raw(@RequestParam String name) {
        File f = new File(BASE, name);
        return ResponseEntity.ok(new FileSystemResource(f));
    }
}
