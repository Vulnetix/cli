package com.acme.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {

    @Deprecated
    @PostMapping("/v1/exports")
    public ResponseEntity<String> createExportV1() {
        return ResponseEntity
                .status(HttpStatus.GONE)
                .body("Use POST /v2/exports");
    }
}
