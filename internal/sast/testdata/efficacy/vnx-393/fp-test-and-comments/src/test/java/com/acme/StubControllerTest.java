package com.acme;

import org.springframework.http.ResponseEntity;

class StubControllerTest {
    ResponseEntity<String> stub() {
        try {
            throw new IllegalStateException();
        } catch (IllegalStateException e) {
            return ResponseEntity.ok("stubbed");
        }
    }
}
