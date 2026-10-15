package com.acme.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/account/2fa")
public class TwoFactorController {

    @GetMapping("/status")
    public ResponseEntity<String> status() {
        return ResponseEntity.ok("disabled");
    }

    @PostMapping("/enable")
~>    public ResponseEntity<Void> enable(@RequestParam String code) {
        throw new UnsupportedOperationException("two-factor enrolment is not available yet");
    }
}
