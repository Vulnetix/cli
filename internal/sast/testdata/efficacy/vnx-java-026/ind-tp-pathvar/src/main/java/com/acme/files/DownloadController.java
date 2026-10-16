package com.acme.files;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class DownloadController {
    private final String exportDir = "/var/data/exports/";

    @GetMapping("/exports/{name}")
    public ResponseEntity<Resource> export(@PathVariable("name") String name) {
        String full = exportDir + name;
~>        Resource r = new FileSystemResource(full);
        return ResponseEntity.ok().body(r);
    }
}
