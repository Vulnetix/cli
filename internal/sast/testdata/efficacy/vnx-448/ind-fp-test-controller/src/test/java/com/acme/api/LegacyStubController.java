package com.acme.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class LegacyStubController {

    @Deprecated
    @GetMapping("/v1/ping")
    String ping() {
        return "pong";
    }
}
