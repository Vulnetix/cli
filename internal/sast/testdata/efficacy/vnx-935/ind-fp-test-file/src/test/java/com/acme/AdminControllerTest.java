package com.acme;

import javax.annotation.security.PermitAll;
import org.springframework.web.bind.annotation.*;

class AdminControllerTest {
    @RestController
    static class Fake {
        @PermitAll
        @GetMapping("/admin/ping")
        String ping() { return "pong"; }
    }
}
