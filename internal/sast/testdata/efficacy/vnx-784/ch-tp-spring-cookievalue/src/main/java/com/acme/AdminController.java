package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {
    @GetMapping("/admin")
~>    public String admin(@CookieValue(value = "role", defaultValue = "user") String role) {
        if (!"admin".equals(role)) {
            return "forbidden";
        }
        return "panel";
    }
}
