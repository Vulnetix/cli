package com.acme.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IngestController {
    private final String ingestToken;

    public IngestController(IngestProperties props) {
        this.ingestToken = props.getKey();
    }

    @PostMapping("/ingest")
    public ResponseEntity<Void> ingest(@RequestHeader("X-Ingest-Key") String providedToken, @RequestBody String body) {
~>        if (!providedToken.equals(ingestToken)) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.accepted().build();
    }
}
