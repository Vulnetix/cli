package com.acme;

public class Notes {
    void run() {
        try {
            work();
        } catch (Exception e) {
            // never write: return ResponseEntity.ok("failed");
            throw new IllegalStateException("work failed", e);
        }
    }
}
