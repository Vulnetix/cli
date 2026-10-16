package com.acme;

import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {
    private final UserService users;

    public AdminController(UserService users) { this.users = users; }

~>    @PreAuthorize("permitAll()")
    @GetMapping("/admin/users")
    public List<User> list() {
        return users.findAll();
    }
}
