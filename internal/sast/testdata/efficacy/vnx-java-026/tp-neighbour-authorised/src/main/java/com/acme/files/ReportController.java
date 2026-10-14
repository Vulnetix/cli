package com.acme.files;

import java.nio.file.Path;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportController {
    private final Path reports = Path.of("/srv/reports");

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/reports/{name}")
    public ResponseEntity<Resource> admin(@PathVariable String name) {
        return ResponseEntity.ok(new FileSystemResource(reports.resolve(name)));
    }

    @GetMapping("/public/reports/{name}")
    public ResponseEntity<Resource> open(
            @PathVariable String name) {
        Path p = reports.resolve(name);
~>        return ResponseEntity.ok(new FileSystemResource(p));
    }
}
