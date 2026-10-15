package com.acme.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class LegacyController {

    @Deprecated
    @PostMapping("/login/legacy")
    public ResponseEntity<Void> legacyLogin() {
        return ResponseEntity.status(HttpStatus.GONE).build();
    }
}
