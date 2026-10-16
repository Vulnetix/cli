package com.acme.files;

import java.security.Principal;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class OwnerDownload {
    @GetMapping("/my/{name}")
    public ResponseEntity<Resource> mine(@PathVariable String name, Principal principal) {
        Resource r = new FileSystemResource("/data/" + principal.getName() + "/" + name);
        return ResponseEntity.ok(r);
    }
}
