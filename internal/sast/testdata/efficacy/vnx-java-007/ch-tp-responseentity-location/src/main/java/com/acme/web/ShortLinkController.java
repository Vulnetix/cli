package com.acme.web;

import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ShortLinkController {
    @GetMapping("/go")
    public ResponseEntity<Void> go(@RequestParam("dest") String dest) {
        return ResponseEntity.status(HttpStatus.FOUND)
~>                .location(URI.create(dest))
                .build();
    }
}
