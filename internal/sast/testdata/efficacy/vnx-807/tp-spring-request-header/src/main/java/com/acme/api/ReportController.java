package com.acme.api;

import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {
    @GetMapping("/reports")
    public String reports(@RequestHeader("X-User-Role") String role,
                          @CookieValue(value = "isAdmin", defaultValue = "false") boolean admin) {
~>        if ("ADMIN".equals(role)) {
            return "all";
        }
~>        if (admin) {
            return "all";
        }
        return "mine";
    }
}
