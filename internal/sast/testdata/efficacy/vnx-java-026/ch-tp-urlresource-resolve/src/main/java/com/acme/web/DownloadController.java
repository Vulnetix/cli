package com.acme.web;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/files")
public class DownloadController {
    private final Path root = Paths.get("/srv/uploads");

    @GetMapping("/{name}")
    public ResponseEntity<Resource> download(@PathVariable String name) throws IOException {
        Path file = root.resolve(name).normalize();
~>        Resource res = new UrlResource(file.toUri());
        return ResponseEntity.ok().body(res);
    }

    @GetMapping("/export")
    public Resource export(@RequestParam(name = "file", required = true) String fileName) {
~>        return new FileSystemResource(new java.io.File("/srv/exports", fileName));
    }
}
