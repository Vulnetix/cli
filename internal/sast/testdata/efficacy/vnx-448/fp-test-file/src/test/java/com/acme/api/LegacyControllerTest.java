package com.acme.api;

import org.springframework.web.bind.annotation.*;

@RestController
class LegacyControllerTest {
    @Deprecated
    @GetMapping("/test-only")
    public String probe() {
        return "ok";
    }
}
