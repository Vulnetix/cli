package com.example;

import jakarta.annotation.security.PermitAll;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public java.util.List<String> users() {
        return java.util.List.of();
    }

    @PermitAll
    @PostMapping("/login")
    public String login() {
        return "ok";
    }

    @PreAuthorize("permitAll()")
    @GetMapping("/public/status")
    public String status() {
        return "up";
    }
}
