package com.acme.web;

import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class ExportController {
    public ResponseEntity<String> export(String id) {
        try {
            return ResponseEntity.ok(exporter.run(id));
        } catch (ExportException ex) {
~>            return ResponseEntity
                .ok()
                .body("export failed: " + ex.getMessage());
        }
    }

    public ResponseEntity<Error> retry(String id) {
        try {
            exporter.retry(id);
            return ResponseEntity.accepted().build();
        } catch (IllegalStateException ex) {
~>            return new ResponseEntity<>(new Error(ex.getMessage()), HttpStatus.OK);
        }
    }

    public void raw(HttpServletResponse resp) {
        try {
            exporter.stream(resp.getOutputStream());
        } catch (java.io.IOException e) {
~>            resp.setStatus(HttpServletResponse.SC_OK);
        }
    }
}
