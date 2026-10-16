package com.acme;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeAdmin {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public java.util.List<User> list() { return users.findAll(); }
}
