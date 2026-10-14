package com.acme.files;

import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.PathResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {
    @GetMapping("/file")
    public ResponseEntity<InputStreamResource> getFile(
            @RequestParam String path) throws IOException {
~>        return ResponseEntity.ok(new InputStreamResource(new FileInputStream(path)));
    }

    @GetMapping("/export")
    public ResponseEntity<PathResource> export(@RequestParam(value = "report", required = true) String report,
                                               @RequestParam int page) {
        String location = "/var/reports/" + report;
~>        return ResponseEntity.ok(new PathResource(location));
    }
}
