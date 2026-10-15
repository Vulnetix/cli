package com.acme.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DownloadController {

    @GetMapping("/download-hint")
    public ResponseEntity<String> hint() {
        String os = System.getProperty("os.name");
        boolean windows = os.toLowerCase().startsWith("win");
        String sep = System.lineSeparator();
        if (windows) {
            return ResponseEntity.ok("Use the .msi installer" + sep);
        }
        return ResponseEntity.ok("Use the .tar.gz archive" + sep);
    }
}
