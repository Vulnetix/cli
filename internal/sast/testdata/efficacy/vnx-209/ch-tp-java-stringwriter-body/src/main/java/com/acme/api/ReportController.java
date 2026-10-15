package com.acme.api;

import java.io.PrintWriter;
import java.io.StringWriter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportController {

    @GetMapping("/report")
    public ResponseEntity<String> report() {
        try {
            return ResponseEntity.ok(build());
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
~>            return ResponseEntity.status(500).body(sw.toString());
        }
    }

    private String build() throws Exception {
        return "";
    }
}
