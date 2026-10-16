package com.acme.files;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class SecureDownload {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/files/{name}")
    public ResponseEntity<Resource> get(@PathVariable String name) {
        return ResponseEntity.ok(new FileSystemResource("/var/admin/" + name));
    }
}
